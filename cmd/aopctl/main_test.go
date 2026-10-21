package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// testToken mixes base64 and other characters, so redacting only base64 runs
// would leave "-suffix7" behind.
var testToken = strings.Repeat("A", 32) + "-suffix7"

const testZone = "023e105f4ecef8ad9ca31a8372d0c353"

type testCA struct {
	cert    *x509.Certificate
	key     crypto.Signer
	certPEM string
	keyPEM  string
}

func newTestCA(t *testing.T, days int) *testCA {
	t.Helper()
	cert, key, err := createCA("Test AOP CA", keyTypeECP256, days, time.Now())
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	keyPEM, err := encodeKeyPEM(key)
	if err != nil {
		t.Fatalf("encode CA key: %v", err)
	}
	return &testCA{cert: cert, key: key, certPEM: encodeCertPEM(cert), keyPEM: keyPEM}
}

// issue returns the PEM of a leaf signed by the CA.
func (ca *testCA) issue(t *testing.T) string {
	t.Helper()
	leaf, _, err := createLeaf(ca.cert, ca.key, "existing leaf", keyTypeECP256, 30, time.Now())
	if err != nil {
		t.Fatalf("issue leaf: %v", err)
	}
	return encodeCertPEM(leaf)
}

func boolPtr(b bool) *bool { return &b }

// fakeCF is a stateful fake of Cloudflare's hostname AOP API.
type fakeCF struct {
	mu       sync.Mutex
	certs    []*fakeCert
	assocs   map[string]*fakeAssoc
	requests []fakeRequest
	uploads  int
	perPage  int

	// Statuses a certificate or association reports on successive GETs
	// after an upload, delete or PUT. The last one repeats; "gone" makes a
	// certificate disappear.
	uploadStatuses []string
	deleteStatuses []string
	assocStatuses  []string

	// hook runs with mu held before the default handling. Returning true
	// means it wrote the response.
	hook func(w http.ResponseWriter, r *http.Request, body []byte) bool
}

type fakeCert struct {
	id       string
	pem      string
	statuses []string
}

type fakeAssoc struct {
	certID   string
	enabled  *bool
	statuses []string
}

type fakeRequest struct {
	method string
	path   string
	query  string
	body   []byte
}

func newFakeCF(t *testing.T) (*fakeCF, *httptest.Server) {
	t.Helper()
	f := &fakeCF{
		assocs:         map[string]*fakeAssoc{},
		perPage:        50,
		uploadStatuses: []string{"pending_deployment", statusActive},
		deleteStatuses: []string{statusPendingDeletion, "gone"},
		assocStatuses:  []string{"pending_deployment", statusActive},
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

// next returns the current status and advances to the next one.
func next(statuses *[]string) string {
	s := (*statuses)[0]
	if len(*statuses) > 1 {
		*statuses = (*statuses)[1:]
	}
	return s
}

func (f *fakeCF) addCert(id, pem string, statuses ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(statuses) == 0 {
		statuses = []string{statusActive}
	}
	f.certs = append(f.certs, &fakeCert{id: id, pem: pem, statuses: statuses})
}

func (f *fakeCF) setAssoc(host, certID string, enabled *bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.assocs[host] = &fakeAssoc{certID: certID, enabled: enabled, statuses: []string{statusActive}}
}

func (f *fakeCF) assocCertID(host string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a := f.assocs[host]; a != nil {
		return a.certID
	}
	return ""
}

func (f *fakeCF) findCert(id string) (int, *fakeCert) {
	for i, c := range f.certs {
		if c.id == id {
			return i, c
		}
	}
	return -1, nil
}

func (f *fakeCF) recorded() []fakeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeRequest(nil), f.requests...)
}

// count returns how many requests used method on a path ending in suffix.
func (f *fakeCF) count(method, suffix string) int {
	n := 0
	for _, r := range f.recorded() {
		if r.method == method && strings.HasSuffix(r.path, suffix) {
			n++
		}
	}
	return n
}

func (f *fakeCF) writes() []fakeRequest {
	var writes []fakeRequest
	for _, r := range f.recorded() {
		if r.method != http.MethodGet {
			writes = append(writes, r)
		}
	}
	return writes
}

func writeEnvelope(w http.ResponseWriter, status int, result any, extra map[string]any) {
	env := map[string]any{"success": status < 300, "errors": []any{}, "messages": []any{}, "result": result}
	for k, v := range extra {
		env[k] = v
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(env)
}

func writeAPIError(w http.ResponseWriter, status, code int, msg string) {
	writeEnvelope(w, status, nil, map[string]any{
		"success": false,
		"errors":  []any{map[string]any{"code": code, "message": msg}},
	})
}

// writeCutOff sends the headers and the start of a JSON body, then closes
// the connection, so reading the body fails with io.ErrUnexpectedEOF.
func writeCutOff(t *testing.T, w http.ResponseWriter, status int) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", "1000")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"success":true,"result":{"id":"`)
	w.(http.Flusher).Flush()
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Errorf("hijack: %v", err)
		return
	}
	_ = conn.Close()
}

// resetConnection resets the connection before any response is sent.
func resetConnection(t *testing.T, w http.ResponseWriter) {
	t.Helper()
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Errorf("hijack: %v", err)
		return
	}
	_ = conn.(*net.TCPConn).SetLinger(0)
	_ = conn.Close()
}

// stall holds a request until the client gives up on it, so the command's
// budget runs out while the request is in flight.
func stall(r *http.Request) {
	<-r.Context().Done()
}

func certJSON(c *fakeCert, status string) map[string]any {
	return map[string]any{
		"id": c.id, "certificate": c.pem, "status": status,
		"expires_on": "2030-01-01T00:00:00Z", "signature": "ECDSAWithSHA256",
	}
}

func (f *fakeCF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, fakeRequest{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, body: body})

	if r.Header.Get("Authorization") != "Bearer "+testToken {
		writeAPIError(w, http.StatusForbidden, 10000, "Authentication error")
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/zones/"+testZone+"/origin_tls_client_auth/hostnames")
	if !ok {
		writeAPIError(w, http.StatusNotFound, 7003, "Could not route")
		return
	}
	if f.hook != nil && f.hook(w, r, body) {
		return
	}

	switch {
	case rest == "" && r.Method == http.MethodPut:
		f.putAssociations(w, body)
	case rest == "/certificates" && r.Method == http.MethodGet:
		f.list(w, r)
	case rest == "/certificates" && r.Method == http.MethodPost:
		f.upload(w, body)
	case strings.HasPrefix(rest, "/certificates/"):
		f.cert(w, r.Method, strings.TrimPrefix(rest, "/certificates/"))
	case strings.HasPrefix(rest, "/") && r.Method == http.MethodGet:
		f.association(w, strings.TrimPrefix(rest, "/"))
	default:
		writeAPIError(w, http.StatusMethodNotAllowed, 10405, "Method not allowed")
	}
}

func (f *fakeCF) list(w http.ResponseWriter, r *http.Request) {
	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}
	totalPages := (len(f.certs) + f.perPage - 1) / f.perPage
	result := []any{}
	for i := (page - 1) * f.perPage; i < len(f.certs) && i < page*f.perPage; i++ {
		result = append(result, certJSON(f.certs[i], f.certs[i].statuses[0]))
	}
	writeEnvelope(w, http.StatusOK, result, map[string]any{"result_info": map[string]any{
		"page": page, "per_page": f.perPage, "total_pages": totalPages, "count": len(result), "total_count": len(f.certs),
	}})
}

func (f *fakeCF) upload(w http.ResponseWriter, body []byte) {
	var req struct {
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"private_key"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Certificate == "" || req.PrivateKey == "" {
		writeAPIError(w, http.StatusBadRequest, 1400, "missing leaf certificate")
		return
	}
	f.uploads++
	c := &fakeCert{
		id:       fmt.Sprintf("new-%d", f.uploads),
		pem:      req.Certificate,
		statuses: append([]string(nil), f.uploadStatuses...),
	}
	f.certs = append(f.certs, c)
	writeEnvelope(w, http.StatusOK, certJSON(c, "initializing"), nil)
}

func (f *fakeCF) cert(w http.ResponseWriter, method, id string) {
	i, c := f.findCert(id)
	if c == nil {
		writeAPIError(w, http.StatusNotFound, 1551, "certificate not found")
		return
	}
	switch method {
	case http.MethodGet:
		status := next(&c.statuses)
		if status == "gone" {
			f.certs = append(f.certs[:i], f.certs[i+1:]...)
			writeAPIError(w, http.StatusNotFound, 1551, "certificate not found")
			return
		}
		writeEnvelope(w, http.StatusOK, certJSON(c, status), nil)
	case http.MethodDelete:
		c.statuses = append([]string(nil), f.deleteStatuses...)
		writeEnvelope(w, http.StatusOK, map[string]any{"id": id}, nil)
	default:
		writeAPIError(w, http.StatusMethodNotAllowed, 10405, "Method not allowed")
	}
}

func (f *fakeCF) association(w http.ResponseWriter, host string) {
	a := f.assocs[host]
	if a == nil {
		writeAPIError(w, http.StatusNotFound, codeNoAssociation, "Auth origin pull setting for this hostname not found.")
		return
	}
	writeEnvelope(w, http.StatusOK, map[string]any{
		"hostname": host, "cert_id": a.certID, "enabled": a.enabled, "status": next(&a.statuses),
	}, nil)
}

// applyAssociation sets one hostname's association, as a PUT does.
func (f *fakeCF) applyAssociation(host, certID string, enabled *bool) {
	f.assocs[host] = &fakeAssoc{certID: certID, enabled: enabled, statuses: append([]string(nil), f.assocStatuses...)}
}

func (f *fakeCF) putAssociations(w http.ResponseWriter, body []byte) {
	var req struct {
		Config []associationConfig `json:"config"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeAPIError(w, http.StatusBadRequest, 1400, "invalid request")
		return
	}
	result := []any{}
	for _, c := range req.Config {
		f.applyAssociation(c.Hostname, c.CertID, c.Enabled)
		result = append(result, map[string]any{"hostname": c.Hostname, "cert_id": c.CertID, "enabled": c.Enabled, "status": "pending_deployment"})
	}
	writeEnvelope(w, http.StatusOK, result, nil)
}

// harness runs the CLI against a fake Cloudflare with injected terminals,
// clock and waits.
type harness struct {
	t    *testing.T
	fake *fakeCF
	srv  *httptest.Server
	ca   *testCA
	env  map[string]string

	stdin     string
	stdoutTTY bool
	stdinTTY  bool
	openTTY   func() (io.ReadWriteCloser, error)
	now       time.Time

	// waits counts poll waits. When waitLimit is set, that wait reports the
	// budget as exhausted. blockWaits makes every wait last until the
	// command's budget runs out, as a poll interval longer than the budget
	// does.
	waits      int
	waitLimit  int
	blockWaits bool
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	fake, srv := newFakeCF(t)
	ca := newTestCA(t, 3650)
	return &harness{
		t:    t,
		fake: fake,
		srv:  srv,
		ca:   ca,
		env: map[string]string{
			"CLOUDFLARE_API_TOKEN": testToken,
			"CLOUDFLARE_ZONE_ID":   testZone,
			"AOP_CA_CERT":          ca.certPEM,
			"AOP_CA_KEY":           ca.keyPEM,
		},
		openTTY: func() (io.ReadWriteCloser, error) {
			return nil, errors.New("no terminal in tests")
		},
	}
}

func (h *harness) run(args ...string) (code int, stdout, stderr string) {
	h.t.Helper()
	var out, errOut bytes.Buffer
	a := &app{
		stdin:            strings.NewReader(h.stdin),
		stdout:           &out,
		stderr:           &errOut,
		getenv:           func(k string) string { return h.env[k] },
		stdoutIsTerminal: func() bool { return h.stdoutTTY },
		stdinIsTerminal:  func() bool { return h.stdinTTY },
		openTTY:          h.openTTY,
		baseURL:          h.srv.URL,
		httpClient:       &http.Client{Timeout: requestTimeout},
		wait: func(ctx context.Context, _ time.Duration) error {
			h.waits++
			if h.blockWaits {
				<-ctx.Done()
				return ctx.Err()
			}
			if h.waitLimit > 0 && h.waits >= h.waitLimit {
				return context.DeadlineExceeded
			}
			return ctx.Err()
		},
		now: func() time.Time {
			if h.now.IsZero() {
				return time.Now()
			}
			return h.now
		},
	}
	code = a.run(args)
	return code, out.String(), errOut.String()
}

// fakeTTY is a terminal that answers with input and records the prompt.
type fakeTTY struct {
	io.Reader
	prompt bytes.Buffer
}

func (t *fakeTTY) Write(p []byte) (int, error) { return t.prompt.Write(p) }
func (t *fakeTTY) Close() error                { return nil }

func TestUsage(t *testing.T) {
	tests := []struct {
		args []string
		code int
	}{
		{nil, 2},
		{[]string{"-h"}, 0},
		{[]string{"help"}, 0},
		{[]string{"leaf", "-h"}, 0},
		{[]string{"leaf", "issue", "-h"}, 0},
		{[]string{"ca"}, 2},
		{[]string{"leaf", "rotate"}, 2},
		{[]string{"leaf", "status", "extra"}, 2},
		{[]string{"leaf", "status", "--bogus"}, 2},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			h := newHarness(t)
			code, stdout, stderr := h.run(tt.args...)
			if code != tt.code {
				t.Fatalf("exit %d, want %d; stderr:\n%s", code, tt.code, stderr)
			}
			if !strings.Contains(stderr, "Usage: aopctl") {
				t.Errorf("stderr has no usage:\n%s", stderr)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
		})
	}
}

func TestDefaultKeyTypes(t *testing.T) {
	h := newHarness(t)
	h.now = time.Now().Truncate(time.Second)

	code, stdout, stderr := h.run("ca", "create")
	if code != 0 {
		t.Fatalf("ca create: exit %d; stderr:\n%s", code, stderr)
	}
	cert, key := parseItemPair(t, stdout)
	if got := describeKey(key.Public()); got != "ECDSA P-256" {
		t.Errorf("ca create key type = %s, want ECDSA P-256", got)
	}
	if got := cert.NotAfter.Sub(cert.NotBefore); got != 3650*24*time.Hour {
		t.Errorf("ca create validity = %s, want 3650 days", got)
	}

	code, _, stderr = h.run("leaf", "issue", "--dry-run", "--hostname", "app.example.com")
	if code != 0 {
		t.Fatalf("leaf issue: exit %d; stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "key type:    ECDSA P-256") {
		t.Errorf("leaf issue plan does not show a P-256 key:\n%s", stderr)
	}
	expires := h.now.UTC().Add(-time.Hour).AddDate(0, 0, 365).Format(time.RFC3339)
	if !strings.Contains(stderr, "expires:     "+expires) {
		t.Errorf("leaf issue plan does not expire after 365 days (%s):\n%s", expires, stderr)
	}
}

func TestUsageErrors(t *testing.T) {
	hosts := make([]string, 101)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("h%d.example.com", i)
	}
	type usageTest struct {
		name string
		args []string
		env  string
	}
	tests := []usageTest{
		{"ca key type", []string{"ca", "create", "--key-type", "ed25519"}, ""},
		{"leaf key type", []string{"leaf", "issue", "--key-type", "rsa-2048", "--hostname", "a.example.com"}, ""},
		{"ca days zero", []string{"ca", "create", "--days", "0"}, ""},
		{"leaf days negative", []string{"leaf", "issue", "--days", "-1", "--hostname", "a.example.com"}, ""},
		{"issue timeout zero", []string{"leaf", "issue", "--timeout", "0s", "--hostname", "a.example.com"}, ""},
		{"associate timeout negative", []string{"leaf", "associate", "--cert-id", "x", "--timeout", "-1s", "--hostname", "a.example.com"}, ""},
		{"prune timeout zero", []string{"leaf", "prune", "--cert-id", "x", "--timeout", "0s", "--hostname", "a.example.com"}, ""},
		{"101 hostnames from env", []string{"leaf", "issue", "--dry-run"}, strings.Join(hosts, ",")},
		{"101 hostname flags", append([]string{"leaf", "issue", "--dry-run"}, hostnameArgs(hosts)...), ""},
		{"associate without cert id", []string{"leaf", "associate", "--hostname", "a.example.com"}, ""},
		{"invalid hostname", []string{"leaf", "status", "--hostname", "*.example.com"}, ""},
	}
	for _, id := range []string{".", "..", "a/b", ""} {
		tests = append(tests,
			usageTest{"associate cert id " + strconv.Quote(id), []string{"leaf", "associate", "--cert-id", id, "--hostname", "a.example.com"}, ""},
			usageTest{"prune cert id " + strconv.Quote(id), []string{"leaf", "prune", "--cert-id", id, "--cert-id", "old", "--yes", "--hostname", "a.example.com"}, ""},
		)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.env["AOP_HOSTNAMES"] = tt.env
			code, stdout, stderr := h.run(tt.args...)
			if code != 2 {
				t.Fatalf("exit %d, want 2; stderr:\n%s", code, stderr)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
			if n := len(h.fake.recorded()); n != 0 {
				t.Errorf("sent %d requests, want none", n)
			}
		})
	}
}

func TestHundredHostnamesAccepted(t *testing.T) {
	h := newHarness(t)
	hosts := make([]string, 100)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("h%d.example.com", i)
	}
	h.env["AOP_HOSTNAMES"] = strings.Join(hosts, " ")
	code, _, stderr := h.run("leaf", "issue", "--dry-run")
	if code != 0 {
		t.Fatalf("exit %d; stderr:\n%s", code, stderr)
	}
	if n := h.fake.count(http.MethodGet, "/hostnames/h99.example.com"); n != 1 {
		t.Errorf("read the 100th hostname %d times, want 1", n)
	}
}

func hostnameArgs(hosts []string) []string {
	var args []string
	for _, h := range hosts {
		args = append(args, "--hostname", h)
	}
	return args
}

func TestHostnames(t *testing.T) {
	tests := []struct {
		name  string
		env   string
		flags []string
		want  []string
		err   bool
	}{
		{
			name: "env normalized",
			env:  " App.Example.COM., b.example.com\nb.example.com\tc.example.com,,",
			want: []string{"app.example.com", "b.example.com", "c.example.com"},
		},
		{
			name:  "flags replace env",
			env:   "a.example.com",
			flags: []string{"X.example.com", " y.example.com. ", "x.example.com"},
			want:  []string{"x.example.com", "y.example.com"},
		},
		{name: "empty", env: " , ", want: nil},
		{name: "wildcard", flags: []string{"*.example.com"}, err: true},
		{name: "port", flags: []string{"a.example.com:443"}, err: true},
		{name: "path", flags: []string{"a.example.com/x"}, err: true},
		{name: "whitespace", flags: []string{"a.example.com b.example.com"}, err: true},
		{name: "wildcard in env", env: "a.example.com,*.example.com", err: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &app{getenv: func(string) string { return tt.env }}
			got, err := a.hostnames(tt.flags)
			if tt.err {
				var usageErr *usageError
				if !errors.As(err, &usageErr) {
					t.Fatalf("err = %v, want a usage error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("hostnames: %v", err)
			}
			if strings.Join(got, " ") != strings.Join(tt.want, " ") {
				t.Errorf("hostnames = %q, want %q", got, tt.want)
			}
		})
	}
}

// go.mod is one of the plugin files Traefik loads, so the CLI must not add
// dependencies to it.
func TestGoModHasNoRequire(t *testing.T) {
	data, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "require") {
			t.Fatalf("go.mod has a require directive: %q", line)
		}
	}
}
