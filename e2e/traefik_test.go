//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"debug/buildinfo"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	moduleName   = "github.com/krystal/traefik-plugin-cloudflare-origin"
	readyTimeout = 60 * time.Second
)

// traefikV3Version matches the version line of the Traefik major the plugin
// targets, capturing the version. mise.lock pins the exact release the suite
// runs against.
var traefikV3Version = regexp.MustCompile(`(?m)^Version:\s+(3\.\S+)$`)

var (
	shippedFiles = []string{".traefik.yml", "go.mod", "cloudflare_origin.go"}
	routedHosts  = []string{
		"protected.test", "open.test", "other.test", "both.test", "allow.test",
		"strict.test", "same.test", "leaf.test", "reverse.test",
	}
)

// env is one running Traefik process plus the fixtures it was built from.
type env struct {
	certs     *fixtures
	backend   *backend
	addr4     string
	addr6     string // empty when IPv6 loopback is unavailable
	fastProxy bool
}

// syncBuffer collects Traefik's output while the process writes to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func requireTraefikVersion(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("traefik")
	if err != nil {
		t.Fatalf("traefik not found in PATH (run via `mise run e2e`): %v", err)
	}
	out, err := exec.Command(bin, "version").CombinedOutput() //nolint:gosec // Runs the traefik binary from PATH by design.
	if err != nil {
		t.Fatalf("traefik version: %v\n%s", err, out)
	}
	m := traefikV3Version.FindSubmatch(out)
	if m == nil {
		t.Fatalf("traefik version is not 3.x:\n%s", out)
	}
	t.Logf("traefik %s", m[1])
	return bin
}

// TestYaegiMatchesTraefik guards test:yaegi's fidelity: the Yaegi CLI must be
// the same version as the interpreter compiled into the Traefik binary.
func TestYaegiMatchesTraefik(t *testing.T) {
	bin := requireTraefikVersion(t)
	info, err := buildinfo.ReadFile(bin)
	if err != nil {
		t.Fatalf("read traefik build info: %v", err)
	}
	var embedded string
	for _, dep := range info.Deps {
		if dep.Path == "github.com/traefik/yaegi" {
			embedded = strings.TrimPrefix(dep.Version, "v")
		}
	}
	if embedded == "" {
		t.Fatal("traefik build info does not list github.com/traefik/yaegi")
	}

	out, err := exec.Command("yaegi", "version").CombinedOutput()
	if err != nil {
		t.Fatalf("yaegi version (run via `mise run e2e`): %v\n%s", err, out)
	}
	if cli := strings.TrimPrefix(strings.TrimSpace(string(out)), "v"); cli != embedded {
		t.Fatalf("yaegi CLI is %s but traefik embeds yaegi %s; align the aqua:traefik/yaegi entry in mise.lock", cli, embedded)
	}
}

func ipv6Available() bool {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// requireIPv6 skips IPv6 cases locally when ::1 cannot be bound, but fails in
// CI where the runner is expected to support it.
func (e *env) requireIPv6(t *testing.T) {
	t.Helper()
	if e.addr6 != "" {
		return
	}
	if os.Getenv("CI") != "" {
		t.Fatal("IPv6 loopback is unavailable, which CI requires")
	}
	t.Skip("IPv6 loopback is unavailable")
}

// freePort returns a port that was free a moment ago. Traefik binds it
// later, so another process can take it in between; startTraefik retries
// once on a bind failure.
func freePort(t *testing.T, host string) string {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("listen on %s: %v", host, err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func startTraefik(t *testing.T, fastProxy bool) *env {
	t.Helper()
	bin := requireTraefikVersion(t)

	dir := t.TempDir()
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	pluginDir := filepath.Join(dir, "plugins-local", "src", moduleName)
	if err := os.MkdirAll(pluginDir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, name := range shippedFiles {
		data, err := os.ReadFile(filepath.Join(repoRoot, name)) //nolint:gosec // name comes from the fixed shippedFiles list.
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pluginDir, name), data, 0o600); err != nil { //nolint:gosec // As above.
			t.Fatal(err)
		}
	}

	e := &env{
		certs:     newFixtures(t, dir, routedHosts),
		backend:   newBackend(t),
		fastProxy: fastProxy,
	}
	writeDynamicConfig(t, dir, e)

	withIPv6 := ipv6Available()
	if !withIPv6 && os.Getenv("CI") != "" {
		t.Fatal("IPv6 loopback is unavailable, which CI requires")
	}

	for attempt := 1; ; attempt++ {
		e.addr4 = freePort(t, "127.0.0.1")
		e.addr6 = ""
		if withIPv6 {
			e.addr6 = freePort(t, "::1")
		}
		writeStaticConfig(t, dir, e)

		log, exited, stop := runTraefik(t, bin, dir)
		err := e.waitReady(exited)
		if err == nil {
			t.Cleanup(func() {
				stop()
				if t.Failed() {
					t.Logf("traefik log:\n%s", log.String())
				}
			})
			return e
		}
		stop()
		if attempt == 1 && strings.Contains(log.String(), "address already in use") {
			t.Logf("traefik could not bind its ports, retrying with new ones")
			continue
		}
		t.Fatalf("traefik did not become ready: %v\ntraefik log:\n%s", err, log.String())
	}
}

func runTraefik(t *testing.T, bin, dir string) (*syncBuffer, <-chan struct{}, func()) {
	t.Helper()
	log := &syncBuffer{}
	cmd := exec.Command(bin, "--configFile="+filepath.Join(dir, "traefik.yml")) //nolint:gosec // Runs the traefik binary from PATH by design.
	cmd.Dir = dir
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		t.Fatalf("start traefik: %v", err)
	}
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()
	stop := func() {
		select {
		case <-exited:
			return
		default:
		}
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-exited:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
	}
	return log, exited, stop
}

// waitReady polls each entrypoint until a routed request reaches the
// backend, which shows that the plugin loaded and the routers exist.
func (e *env) waitReady(exited <-chan struct{}) error {
	deadline := time.Now().Add(readyTimeout)
	for _, addr := range []string{e.addr4, e.addr6} {
		if addr == "" {
			continue
		}
		var lastErr error
		for {
			select {
			case <-exited:
				return errors.New("traefik exited")
			default:
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("timed out on %s, last error: %w", addr, lastErr)
			}
			lastErr = e.probe(addr)
			if lastErr == nil {
				break
			}
			select {
			case <-exited:
				return errors.New("traefik exited")
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	return nil
}

func (e *env) probe(addr string) error {
	client := e.client(addr, &tls.Config{ServerName: "open.test"}, false)
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://open.test/", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func writeStaticConfig(t *testing.T, dir string, e *env) {
	t.Helper()
	var b strings.Builder
	b.WriteString(`global:
  checkNewVersion: false
  sendAnonymousUsage: false
log:
  level: INFO
entryPoints:
`)
	entrypoint := func(name, addr string) {
		fmt.Fprintf(&b, `  %s:
    address: %q
    http:
      middlewares:
        - cfo-entry@file
`, name, addr)
	}
	entrypoint("v4", e.addr4)
	if e.addr6 != "" {
		entrypoint("v6", e.addr6)
	}
	fmt.Fprintf(&b, `experimental:
  localPlugins:
    cfo:
      moduleName: %s
`, moduleName)
	if e.fastProxy {
		// debug makes the fast proxy add X-Traefik-Fast-Proxy to backend
		// requests, so tests can prove it handled them.
		b.WriteString("  fastProxy:\n    debug: true\n")
	}
	fmt.Fprintf(&b, `providers:
  file:
    filename: %q
`, filepath.Join(dir, "dynamic.yml"))
	writeFile(t, filepath.Join(dir, "traefik.yml"), b.String())
}

// writeDynamicConfig declares one router per scenario. The entrypoint
// instance pins the AOP CA; router-level instances vary the pin to exercise
// chaining.
func writeDynamicConfig(t *testing.T, dir string, e *env) {
	t.Helper()
	c := e.certs
	aopCA := fingerprint(c.aopCA.cert)
	cfLeaf := fingerprint(c.cfLeaf.Leaf)
	otherCA := fingerprint(c.otherCA.cert)

	config := fmt.Sprintf(`http:
  middlewares:
    cfo-entry:
      plugin:
        cfo:
          clientCertFingerprints: [%[1]q]
          protectedHosts: [protected.test, both.test]
          directAccessCIDRs: ["::1"]
    cfo-same:
      plugin:
        cfo:
          clientCertFingerprints: [%[1]q]
          protectAllHosts: true
          directAccessCIDRs: ["::1"]
    cfo-leaf:
      plugin:
        cfo:
          clientCertFingerprints: [%[2]q]
          protectAllHosts: true
          directAccessCIDRs: ["192.0.2.0/24", "::1"]
    cfo-other:
      plugin:
        cfo:
          clientCertFingerprints: [%[3]q]
          protectAllHosts: true
    cfo-strict:
      plugin:
        cfo:
          clientCertFingerprints: [%[1]q]
          allowMissingClientIP: false
    allow-doc:
      ipAllowList:
        sourceRange: ["203.0.113.0/24"]
  routers:
    protected:
      rule: Host(%[4]s)
      service: echo
      tls: {}
    open:
      rule: Host(%[5]s)
      service: echo
      tls: {}
    other:
      rule: Host(%[6]s)
      service: echo
      tls:
        options: other
    both:
      rule: Host(%[7]s)
      service: echo
      tls:
        options: both
    allow:
      rule: Host(%[8]s)
      service: echo
      middlewares: [allow-doc]
      tls: {}
    strict:
      rule: Host(%[9]s)
      service: echo
      middlewares: [cfo-strict]
      tls: {}
    same:
      rule: Host(%[10]s)
      service: echo
      middlewares: [cfo-same]
      tls: {}
    leaf:
      rule: Host(%[11]s)
      service: echo
      middlewares: [cfo-leaf]
      tls: {}
    reverse:
      rule: Host(%[12]s)
      service: echo
      middlewares: [cfo-other]
      tls:
        options: other
  services:
    echo:
      loadBalancer:
        servers:
          - url: %[13]q
tls:
  certificates:
    - certFile: %[14]q
      keyFile: %[15]q
  options:
    default:
      clientAuth:
        caFiles: [%[16]q]
        clientAuthType: VerifyClientCertIfGiven
    other:
      clientAuth:
        caFiles: [%[17]q]
        clientAuthType: VerifyClientCertIfGiven
    both:
      clientAuth:
        caFiles: [%[16]q, %[17]q]
        clientAuthType: VerifyClientCertIfGiven
`,
		aopCA, cfLeaf, otherCA,
		"`protected.test`", "`open.test`", "`other.test`", "`both.test`", "`allow.test`",
		"`strict.test`", "`same.test`", "`leaf.test`", "`reverse.test`",
		e.backend.server.URL, c.serverCert, c.serverKey, c.aopCAFile, c.otherCAFile,
	)
	writeFile(t, filepath.Join(dir, "dynamic.yml"), config)
}

// assertProxy checks which Traefik proxy implementation forwarded a request.
func (e *env) assertProxy(t *testing.T, seen http.Header) {
	t.Helper()
	got := seen.Get("X-Traefik-Fast-Proxy")
	if e.fastProxy && got != "enabled" {
		t.Errorf("X-Traefik-Fast-Proxy = %q, want the fast proxy to forward the request", got)
	}
	if !e.fastProxy && got != "" {
		t.Errorf("X-Traefik-Fast-Proxy = %q, want the standard proxy to forward the request", got)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// client returns an HTTP client that dials addr whatever the URL host, so
// tests control SNI and Host independently.
func (e *env) client(addr string, cfg *tls.Config, h2 bool) *http.Client {
	cfg = cfg.Clone()
	cfg.RootCAs = e.certs.serverPool
	if !h2 {
		cfg.NextProtos = []string{"http/1.1"}
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			},
			TLSClientConfig:   cfg,
			ForceAttemptHTTP2: h2,
			DisableKeepAlives: true,
		},
	}
}
