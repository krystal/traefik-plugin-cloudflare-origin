package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	hostA = "a.example.com"
	hostB = "b.example.com"
	hostC = "c.example.com"
	hostD = "d.example.com"
)

// issueHarness has hostA and hostB on old-1, hostC on old-2 and hostD with
// no association.
func issueHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	h.fake.addCert("old-1", h.ca.issue(t))
	h.fake.addCert("old-2", h.ca.issue(t))
	h.fake.setAssoc(hostA, "old-1", boolPtr(true))
	h.fake.setAssoc(hostB, "old-1", boolPtr(true))
	h.fake.setAssoc(hostC, "old-2", boolPtr(true))
	h.env["AOP_HOSTNAMES"] = strings.Join([]string{hostA, hostB, hostC, hostD}, ",")
	return h
}

// requestsAfter returns the requests recorded after the first one matching
// method and suffix.
func requestsAfter(reqs []fakeRequest, method, suffix string) []fakeRequest {
	for i, r := range reqs {
		if r.method == method && strings.HasSuffix(r.path, suffix) {
			return reqs[i+1:]
		}
	}
	return nil
}

func countIn(reqs []fakeRequest, method, suffix string) int {
	n := 0
	for _, r := range reqs {
		if r.method == method && strings.HasSuffix(r.path, suffix) {
			n++
		}
	}
	return n
}

func TestLeafIssueDryRun(t *testing.T) {
	h := issueHarness(t)
	code, _, stderr := h.run("leaf", "issue", "--dry-run")
	if code != 0 {
		t.Fatalf("exit %d; stderr:\n%s", code, stderr)
	}
	if w := h.fake.writes(); len(w) != 0 {
		t.Errorf("dry run sent %d write requests", len(w))
	}
	for _, want := range []string{
		hostA + ": old-1 (enabled=true) -> new",
		hostC + ": old-2 (enabled=true) -> new",
		hostD + ": none -> new",
		"Dry run: nothing changed.",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
}

func TestLeafIssue(t *testing.T) {
	h := issueHarness(t)
	code, stdout, stderr := h.run("leaf", "issue")
	if code != 0 {
		t.Fatalf("exit %d; stderr:\n%s", code, stderr)
	}
	reqs := h.fake.recorded()

	var upload struct {
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"private_key"`
	}
	for _, r := range reqs {
		if r.method == http.MethodPost {
			if err := json.Unmarshal(r.body, &upload); err != nil {
				t.Fatalf("upload body: %v", err)
			}
		}
	}
	leaf, err := parseCertPEM(upload.Certificate)
	if err != nil {
		t.Fatalf("uploaded certificate: %v", err)
	}
	if err := verifyLeaf(leaf, h.ca.cert, leaf.NotBefore.Add(2*time.Hour)); err != nil {
		t.Errorf("uploaded leaf does not verify for client auth: %v", err)
	}
	key, err := parseKeyPEM(upload.PrivateKey)
	if err != nil {
		t.Fatalf("uploaded key is not PKCS#8: %v", err)
	}
	if !keyMatchesCert(leaf, key) {
		t.Error("uploaded key does not match the uploaded certificate")
	}
	keyLine := strings.Split(upload.PrivateKey, "\n")[1]
	if strings.Contains(stdout+stderr, keyLine) {
		t.Error("output contains the leaf key")
	}

	if n := countIn(reqs, http.MethodGet, "/certificates/new-1"); n < 2 {
		t.Errorf("polled the new certificate %d times, want it polled to active", n)
	}

	var put struct {
		Config []struct {
			Hostname string `json:"hostname"`
			CertID   string `json:"cert_id"`
			Enabled  *bool  `json:"enabled"`
		} `json:"config"`
	}
	if countIn(reqs, http.MethodPut, "/hostnames") != 1 {
		t.Fatal("want exactly one PUT")
	}
	for _, r := range reqs {
		if r.method == http.MethodPut {
			if err := json.Unmarshal(r.body, &put); err != nil {
				t.Fatalf("PUT body: %v", err)
			}
		}
	}
	var putHosts []string
	for _, c := range put.Config {
		putHosts = append(putHosts, c.Hostname)
		if c.CertID != "new-1" || c.Enabled == nil || !*c.Enabled {
			t.Errorf("PUT entry %+v, want new-1 enabled", c)
		}
	}
	if got := strings.Join(putHosts, ","); got != h.env["AOP_HOSTNAMES"] {
		t.Errorf("PUT hostnames %s", got)
	}
	afterPut := requestsAfter(reqs, http.MethodPut, "/hostnames")
	for _, host := range []string{hostA, hostB, hostC, hostD} {
		if countIn(afterPut, http.MethodGet, "/hostnames/"+host) < 2 {
			t.Errorf("did not poll %s until active", host)
		}
		if got := h.fake.assocCertID(host); got != "new-1" {
			t.Errorf("%s uses %q, want new-1", host, got)
		}
	}
	if n := countIn(reqs, http.MethodDelete, ""); n != 0 {
		t.Errorf("sent %d DELETEs", n)
	}

	for _, want := range []string{
		"They no longer use: old-1, old-2",
		"aopctl leaf prune --cert-id old-1 --cert-id old-2 --hostname a.example.com --hostname b.example.com --hostname c.example.com --hostname d.example.com",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
}

func TestLeafIssueFailures(t *testing.T) {
	t.Run("no free slot", func(t *testing.T) {
		h := issueHarness(t)
		for i := 0; i < 8; i++ {
			h.fake.addCert("spare-"+string(rune('a'+i)), h.ca.issue(t))
		}
		code, _, stderr := h.run("leaf", "issue")
		if code != 1 || !strings.Contains(stderr, "the zone has 10 hostname certificates") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if w := h.fake.writes(); len(w) != 0 {
			t.Errorf("sent %d write requests", len(w))
		}
	})

	t.Run("upload transport error", func(t *testing.T) {
		h := issueHarness(t)
		h.fake.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodPost {
				return false
			}
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return true
			}
			_ = conn.(*net.TCPConn).SetLinger(0)
			_ = conn.Close()
			return true
		}
		code, _, stderr := h.run("leaf", "issue")
		if code != 1 || !strings.Contains(stderr, "upload outcome unknown") || !strings.Contains(stderr, "aopctl leaf status before retrying") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if strings.Contains(stderr, "To resume") {
			t.Errorf("printed recovery commands without a certificate ID:\n%s", stderr)
		}
		if n := h.fake.count(http.MethodPut, "/hostnames"); n != 0 {
			t.Errorf("sent %d PUTs", n)
		}
	})

	t.Run("upload result with an undecodable ID", func(t *testing.T) {
		h := issueHarness(t)
		h.fake.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodPost {
				return false
			}
			writeEnvelope(w, http.StatusOK, map[string]any{"id": 1, "status": "initializing"}, nil)
			return true
		}
		code, _, stderr := h.run("leaf", "issue")
		if code != 1 || !strings.Contains(stderr, "upload outcome unknown") || !strings.Contains(stderr, "aopctl leaf status before retrying") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if n := h.fake.count(http.MethodPut, "/hostnames"); n != 0 {
			t.Errorf("sent %d PUTs", n)
		}
	})

	t.Run("upload rejected", func(t *testing.T) {
		h := issueHarness(t)
		h.fake.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodPost {
				return false
			}
			writeAPIError(w, http.StatusBadRequest, 1400, "missing leaf certificate")
			return true
		}
		code, _, stderr := h.run("leaf", "issue")
		if code != 1 || !strings.Contains(stderr, "upload failed") || strings.Contains(stderr, "outcome unknown") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if n := h.fake.count(http.MethodPut, "/hostnames"); n != 0 {
			t.Errorf("sent %d PUTs", n)
		}
	})

	t.Run("certificate never active", func(t *testing.T) {
		h := issueHarness(t)
		h.fake.uploadStatuses = []string{"pending_deployment"}
		h.waitLimit = 3
		code, _, stderr := h.run("leaf", "issue")
		if code != 1 || !strings.Contains(stderr, "timed out waiting for certificate new-1 to become active: last status pending_deployment") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if n := h.fake.count(http.MethodPut, "/hostnames"); n != 0 {
			t.Errorf("sent %d PUTs", n)
		}
	})

	t.Run("deployment timed out", func(t *testing.T) {
		h := issueHarness(t)
		h.fake.uploadStatuses = []string{"pending_deployment", statusDeploymentTimedOut}
		code, _, stderr := h.run("leaf", "issue")
		if code != 1 || !strings.Contains(stderr, "certificate new-1 is deployment_timed_out") || !strings.Contains(stderr, "New certificate: new-1") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if n := h.fake.count(http.MethodPut, "/hostnames"); n != 0 {
			t.Errorf("sent %d PUTs", n)
		}
	})

	t.Run("PUT fails", func(t *testing.T) {
		h := issueHarness(t)
		h.fake.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodPut {
				return false
			}
			writeAPIError(w, http.StatusInternalServerError, 1000, "internal error")
			return true
		}
		code, _, stderr := h.run("leaf", "issue")
		if code != 1 {
			t.Fatalf("exit %d; stderr:\n%s", code, stderr)
		}
		for _, want := range []string{
			"New certificate: new-1",
			"aopctl leaf associate --cert-id new-1 --hostname a.example.com --hostname b.example.com --hostname c.example.com --hostname d.example.com",
			"aopctl leaf associate --cert-id old-1 --hostname a.example.com --hostname b.example.com",
			"aopctl leaf associate --cert-id old-2 --hostname c.example.com",
		} {
			if !strings.Contains(stderr, want) {
				t.Errorf("stderr lacks %q:\n%s", want, stderr)
			}
		}
	})

	t.Run("association never active", func(t *testing.T) {
		h := issueHarness(t)
		h.fake.assocStatuses = []string{"pending_deployment"}
		h.waitLimit = 4
		code, _, stderr := h.run("leaf", "issue")
		if code != 1 {
			t.Fatalf("exit %d; stderr:\n%s", code, stderr)
		}
		for _, want := range []string{
			"timed out waiting for hostnames to use certificate new-1",
			hostA + ": new-1 (enabled=true, status=pending_deployment)",
			"To resume, run:",
		} {
			if !strings.Contains(stderr, want) {
				t.Errorf("stderr lacks %q:\n%s", want, stderr)
			}
		}
	})

	t.Run("preflight association error", func(t *testing.T) {
		h := issueHarness(t)
		h.fake.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/hostnames/"+hostB) {
				writeAPIError(w, http.StatusNotFound, 1000, "not found")
				return true
			}
			return false
		}
		code, _, stderr := h.run("leaf", "issue")
		if code != 1 || !strings.Contains(stderr, "read association for b.example.com") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if w := h.fake.writes(); len(w) != 0 {
			t.Errorf("sent %d write requests", len(w))
		}
	})

	t.Run("disabled hostname", func(t *testing.T) {
		h := issueHarness(t)
		h.fake.setAssoc(hostC, "old-2", boolPtr(false))
		code, _, stderr := h.run("leaf", "issue")
		if code != 1 || !strings.Contains(stderr, "c.example.com has AOP disabled") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if w := h.fake.writes(); len(w) != 0 {
			t.Errorf("sent %d write requests", len(w))
		}
	})
}

// A response to the upload whose other fields drifted still yields the ID.
func TestLeafIssueUploadDrift(t *testing.T) {
	h := issueHarness(t)
	h.fake.hook = func(w http.ResponseWriter, r *http.Request, body []byte) bool {
		if r.Method != http.MethodPost {
			return false
		}
		h.fake.upload(httptest.NewRecorder(), body)
		writeEnvelope(w, http.StatusOK, map[string]any{"id": "new-1", "status": "initializing", "expires_on": 1893456000}, nil)
		return true
	}
	code, stdout, stderr := h.run("leaf", "issue")
	if code != 0 {
		t.Fatalf("exit %d; stderr:\n%s", code, stderr)
	}
	reqs := h.fake.recorded()
	if n := countIn(requestsAfter(reqs, http.MethodPost, "/certificates"), http.MethodGet, "/certificates/new-1"); n < 2 {
		t.Errorf("polled new-1 %d times after the upload, want it polled to active", n)
	}
	if !strings.Contains(stdout, "now use certificate new-1") {
		t.Errorf("stdout:\n%s", stdout)
	}
}

// TestLeafIssueTransientPolling covers polling reads that fail with HTTP 429
// or a 5xx.
func TestLeafIssueTransientPolling(t *testing.T) {
	// failFirst answers the first len(statuses) GETs whose path ends in suffix
	// with those statuses, after a PUT when afterPut is set.
	failFirst := func(h *harness, suffix string, afterPut bool, statuses ...int) {
		put := false
		h.fake.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method == http.MethodPut {
				put = true
			}
			if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, suffix) || (afterPut && !put) || len(statuses) == 0 {
				return false
			}
			status := statuses[0]
			statuses = statuses[1:]
			if status == http.StatusTooManyRequests {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "rate limited")
				return true
			}
			writeAPIError(w, status, 1000, "temporarily unavailable")
			return true
		}
	}

	t.Run("certificate polling recovers", func(t *testing.T) {
		h := issueHarness(t)
		h.waitLimit = 20
		failFirst(h, "/certificates/new-1", false, http.StatusServiceUnavailable, http.StatusTooManyRequests)
		code, _, stderr := h.run("leaf", "issue")
		if code != 0 {
			t.Fatalf("exit %d; stderr:\n%s", code, stderr)
		}
		if got := h.fake.assocCertID(hostA); got != "new-1" {
			t.Errorf("%s uses %q, want new-1", hostA, got)
		}
	})

	t.Run("association polling recovers", func(t *testing.T) {
		h := issueHarness(t)
		h.waitLimit = 20
		failFirst(h, "/hostnames/"+hostA, true, http.StatusServiceUnavailable, http.StatusTooManyRequests)
		code, _, stderr := h.run("leaf", "issue")
		if code != 0 {
			t.Fatalf("exit %d; stderr:\n%s", code, stderr)
		}
		if n := countIn(requestsAfter(h.fake.recorded(), http.MethodPut, "/hostnames"), http.MethodGet, "/hostnames/"+hostA); n < 4 {
			t.Errorf("polled %s %d times after the PUT, want the two failures retried", hostA, n)
		}
	})

	t.Run("budget runs out", func(t *testing.T) {
		h := issueHarness(t)
		h.waitLimit = 3
		failFirst(h, "/certificates/new-1", false, http.StatusServiceUnavailable, http.StatusServiceUnavailable, http.StatusServiceUnavailable, http.StatusServiceUnavailable)
		code, _, stderr := h.run("leaf", "issue")
		if code != 1 || !strings.Contains(stderr, "timed out waiting for certificate new-1 to become active: last error: GET /zones/{zone}/origin_tls_client_auth/hostnames/certificates/new-1: HTTP 503") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if n := h.fake.count(http.MethodGet, "/certificates/new-1"); n != 3 {
			t.Errorf("polled %d times, want 3", n)
		}
	})

	t.Run("other errors fail at once", func(t *testing.T) {
		h := issueHarness(t)
		h.waitLimit = 20
		failFirst(h, "/certificates/new-1", false, http.StatusBadRequest)
		code, _, stderr := h.run("leaf", "issue")
		if code != 1 || !strings.Contains(stderr, "check certificate new-1: GET /zones/{zone}/origin_tls_client_auth/hostnames/certificates/new-1: HTTP 400") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if n := h.fake.count(http.MethodGet, "/certificates/new-1"); n != 1 {
			t.Errorf("polled %d times, want 1", n)
		}
	})
}

func TestLeafIssueAssociationTimedOut(t *testing.T) {
	t.Run("stale on the old certificate", func(t *testing.T) {
		h := issueHarness(t)
		h.waitLimit = 20
		// hostA still reports old-1, timed out, for two polls after the PUT.
		put, stale := false, 0
		h.fake.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method == http.MethodPut {
				put = true
				return false
			}
			if !put || r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/hostnames/"+hostA) || stale == 2 {
				return false
			}
			stale++
			writeEnvelope(w, http.StatusOK, map[string]any{
				"hostname": hostA, "cert_id": "old-1", "enabled": true, "status": statusDeploymentTimedOut,
			}, nil)
			return true
		}
		code, _, stderr := h.run("leaf", "issue")
		if code != 0 {
			t.Fatalf("exit %d; stderr:\n%s", code, stderr)
		}
		if got := h.fake.assocCertID(hostA); got != "new-1" {
			t.Errorf("%s uses %q, want new-1", hostA, got)
		}
	})

	t.Run("timed out on the new certificate", func(t *testing.T) {
		h := issueHarness(t)
		h.waitLimit = 20
		h.fake.assocStatuses = []string{"pending_deployment", statusDeploymentTimedOut}
		code, _, stderr := h.run("leaf", "issue")
		if code != 1 || !strings.Contains(stderr, "association for a.example.com is deployment_timed_out") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if h.waits != 2 {
			t.Errorf("waited %d times, want 2: one for the certificate and one for the associations", h.waits)
		}
	})
}

// commandLines returns the printed aopctl commands that start with prefix,
// as argument lists without "aopctl".
func commandLines(output, prefix string) [][]string {
	var cmds [][]string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			cmds = append(cmds, strings.Fields(line)[1:])
		}
	}
	return cmds
}

func TestLeafIssueLastSlotRecovery(t *testing.T) {
	h := issueHarness(t)
	for i := 0; i < 7; i++ {
		h.fake.addCert("spare-"+string(rune('a'+i)), h.ca.issue(t))
	}
	h.fake.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
		if r.Method != http.MethodPut {
			return false
		}
		writeAPIError(w, http.StatusInternalServerError, 1000, "internal error")
		return true
	}
	code, _, stderr := h.run("leaf", "issue")
	if code != 1 {
		t.Fatalf("issue: exit %d; stderr:\n%s", code, stderr)
	}
	resume := commandLines(stderr, "aopctl leaf associate --cert-id new-1")
	if len(resume) != 1 {
		t.Fatalf("want one resume command, got %q", resume)
	}

	h.fake.hook = nil
	before := len(h.fake.recorded())
	code, _, stderr = h.run(resume[0]...)
	if code != 0 {
		t.Fatalf("resume: exit %d; stderr:\n%s", code, stderr)
	}
	for _, host := range []string{hostA, hostB, hostC, hostD} {
		if got := h.fake.assocCertID(host); got != "new-1" {
			t.Errorf("%s uses %q, want new-1", host, got)
		}
	}
	if n := countIn(h.fake.recorded()[before:], http.MethodGet, "/certificates"); n != 0 {
		t.Errorf("resume listed certificates %d times; it must not need a free slot", n)
	}
}

func TestLeafIssueRollbackOutput(t *testing.T) {
	h := issueHarness(t)
	// The PUT applies to hostA and hostC only, then fails.
	h.fake.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
		if r.Method != http.MethodPut {
			return false
		}
		h.fake.applyAssociation(hostA, "new-1", boolPtr(true))
		h.fake.applyAssociation(hostC, "new-1", boolPtr(true))
		writeAPIError(w, http.StatusInternalServerError, 1000, "internal error")
		return true
	}
	code, _, stderr := h.run("leaf", "issue")
	if code != 1 {
		t.Fatalf("issue: exit %d; stderr:\n%s", code, stderr)
	}
	for _, want := range []string{
		hostA + ": old-1 (enabled=true, status=active) -> new-1 (enabled=true, status=pending_deployment)",
		hostB + ": old-1 (enabled=true, status=active) -> old-1 (enabled=true, status=active)",
		hostD + ": none -> none",
		`{"config":[{"hostname":"d.example.com","cert_id":"new-1","enabled":null}]}`,
		"PUT /zones/{zone}/origin_tls_client_auth/hostnames",
		"Cloudflare dashboard",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	rollback := commandLines(stderr, "aopctl leaf associate --cert-id old-")
	got := make([]string, len(rollback))
	for i, args := range rollback {
		got[i] = strings.Join(args, " ")
	}
	want := []string{
		"leaf associate --cert-id old-1 --hostname a.example.com --hostname b.example.com",
		"leaf associate --cert-id old-2 --hostname c.example.com",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("rollback commands:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	h.fake.hook = nil
	for _, args := range rollback {
		if code, _, stderr := h.run(args...); code != 0 {
			t.Fatalf("%v: exit %d; stderr:\n%s", args, code, stderr)
		}
	}
	for host, want := range map[string]string{hostA: "old-1", hostB: "old-1", hostC: "old-2", hostD: ""} {
		if got := h.fake.assocCertID(host); got != want {
			t.Errorf("%s uses %q after rollback, want %q", host, got, want)
		}
	}
}

// TestLeafIssueOtherCA covers a CA rotation: AOP_CA_CERT is the new CA, and
// old-1 was signed by the old one.
func TestLeafIssueOtherCA(t *testing.T) {
	setup := func(t *testing.T) (*harness, *testCA) {
		h := newHarness(t)
		oldCA := newTestCA(t, 3650)
		h.fake.addCert("old-1", oldCA.issue(t))
		h.fake.addCert("cur-1", h.ca.issue(t))
		h.fake.setAssoc(hostA, "old-1", boolPtr(true))
		h.fake.setAssoc(hostB, "cur-1", boolPtr(true))
		h.env["AOP_HOSTNAMES"] = hostA + "," + hostB
		return h, oldCA
	}

	t.Run("rollback", func(t *testing.T) {
		h, oldCA := setup(t)
		// The PUT applies to hostA only, then fails.
		h.fake.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodPut {
				return false
			}
			h.fake.applyAssociation(hostA, "new-1", boolPtr(true))
			writeAPIError(w, http.StatusInternalServerError, 1000, "internal error")
			return true
		}
		code, _, stderr := h.run("leaf", "issue")
		if code != 1 {
			t.Fatalf("issue: exit %d; stderr:\n%s", code, stderr)
		}
		if !strings.Contains(stderr, "AOP_CA_CERT did not sign old-1, so run the next command with AOP_CA_CERT set to the CA that did") {
			t.Errorf("rollback lacks the other-CA note for old-1:\n%s", stderr)
		}
		if strings.Contains(stderr, "did not sign cur-1") {
			t.Errorf("rollback has an other-CA note for cur-1:\n%s", stderr)
		}
		rollback := commandLines(stderr, "aopctl leaf associate --cert-id old-1")
		if len(rollback) != 1 {
			t.Fatalf("want one rollback command for old-1, got %q", rollback)
		}

		h.fake.hook = nil
		code, _, stderr = h.run(rollback[0]...)
		if code != 1 || !strings.Contains(stderr, "certificate old-1 is not signed by AOP_CA_CERT") {
			t.Errorf("with the new CA: exit %d; stderr:\n%s", code, stderr)
		}
		if got := h.fake.assocCertID(hostA); got != "new-1" {
			t.Errorf("%s uses %q after a refused rollback, want new-1", hostA, got)
		}

		h.env["AOP_CA_CERT"] = oldCA.certPEM
		if code, _, stderr := h.run(rollback[0]...); code != 0 {
			t.Fatalf("with the old CA: exit %d; stderr:\n%s", code, stderr)
		}
		if got := h.fake.assocCertID(hostA); got != "old-1" {
			t.Errorf("%s uses %q after rollback, want old-1", hostA, got)
		}
	})

	t.Run("prune hint", func(t *testing.T) {
		h, _ := setup(t)
		code, stdout, stderr := h.run("leaf", "issue")
		if code != 0 {
			t.Fatalf("exit %d; stderr:\n%s", code, stderr)
		}
		for _, want := range []string{
			"aopctl leaf prune --cert-id cur-1 --hostname a.example.com --hostname b.example.com\n",
			"AOP_CA_CERT did not sign old-1, so run the next command with AOP_CA_CERT set to the CA that did",
			"aopctl leaf prune --cert-id old-1 --hostname a.example.com --hostname b.example.com\n",
		} {
			if !strings.Contains(stdout, want) {
				t.Errorf("stdout lacks %q:\n%s", want, stdout)
			}
		}
	})
}

func TestLeafAssociate(t *testing.T) {
	setup := func(t *testing.T) *harness {
		h := newHarness(t)
		h.fake.addCert("good", h.ca.issue(t))
		h.fake.addCert("foreign", newTestCA(t, 3650).issue(t))
		h.fake.addCert("deploying", h.ca.issue(t), "pending_deployment")
		h.env["AOP_HOSTNAMES"] = hostA + " " + hostB
		h.fake.setAssoc(hostA, "old", boolPtr(true))
		return h
	}

	for _, tt := range []struct{ id, want string }{
		{"foreign", "certificate foreign is not signed by AOP_CA_CERT"},
		{"deploying", "certificate deploying is pending_deployment, not active"},
		{"missing", "HTTP 404"},
	} {
		t.Run("refuses "+tt.id, func(t *testing.T) {
			h := setup(t)
			code, _, stderr := h.run("leaf", "associate", "--cert-id", tt.id)
			if code != 1 || !strings.Contains(stderr, tt.want) {
				t.Errorf("exit %d; stderr:\n%s", code, stderr)
			}
			if w := h.fake.writes(); len(w) != 0 {
				t.Errorf("sent %d write requests", len(w))
			}
		})
	}

	t.Run("refuses a disabled hostname", func(t *testing.T) {
		h := setup(t)
		h.fake.setAssoc(hostB, "old", boolPtr(false))
		code, _, stderr := h.run("leaf", "associate", "--cert-id", "good")
		if code != 1 || !strings.Contains(stderr, "b.example.com has AOP disabled") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if w := h.fake.writes(); len(w) != 0 {
			t.Errorf("sent %d write requests", len(w))
		}
	})

	t.Run("dry run", func(t *testing.T) {
		h := setup(t)
		code, _, stderr := h.run("leaf", "associate", "--cert-id", "good", "--dry-run")
		if code != 0 {
			t.Fatalf("exit %d; stderr:\n%s", code, stderr)
		}
		if !strings.Contains(stderr, hostA+": old (enabled=true, status=active) -> good") || !strings.Contains(stderr, hostB+": none -> good") {
			t.Errorf("stderr:\n%s", stderr)
		}
		if w := h.fake.writes(); len(w) != 0 {
			t.Errorf("sent %d write requests", len(w))
		}
	})

	t.Run("associates", func(t *testing.T) {
		h := setup(t)
		code, stdout, stderr := h.run("leaf", "associate", "--cert-id", "good")
		if code != 0 {
			t.Fatalf("exit %d; stderr:\n%s", code, stderr)
		}
		reqs := h.fake.recorded()
		if w := h.fake.writes(); len(w) != 1 || w[0].method != http.MethodPut {
			t.Errorf("writes = %+v, want one PUT", w)
		}
		afterPut := requestsAfter(reqs, http.MethodPut, "/hostnames")
		for _, host := range []string{hostA, hostB} {
			if countIn(afterPut, http.MethodGet, "/hostnames/"+host) < 2 {
				t.Errorf("did not poll %s until active", host)
			}
			if got := h.fake.assocCertID(host); got != "good" {
				t.Errorf("%s uses %q", host, got)
			}
		}
		if !strings.Contains(stdout, "now use certificate good") {
			t.Errorf("stdout:\n%s", stdout)
		}
	})
}

func TestLeafStatus(t *testing.T) {
	h := newHarness(t)
	minePEM := h.ca.issue(t)
	h.fake.addCert("mine", minePEM)
	h.fake.addCert("foreign", newTestCA(t, 3650).issue(t))
	h.fake.setAssoc(hostA, "mine", boolPtr(true))
	h.env["AOP_HOSTNAMES"] = hostA + "," + hostB
	mineCert, err := parseCertPEM(minePEM)
	if err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := h.run("leaf", "status")
	if code != 0 {
		t.Fatalf("exit %d; stderr:\n%s", code, stderr)
	}
	mine, foreign, _ := strings.Cut(strings.SplitN(stdout, "  mine\n", 2)[1], "  foreign\n")
	for _, want := range []string{"status:    active", "subject:   existing leaf", "key type:  ECDSA P-256", "days left", "signed by AOP_CA_CERT: yes", "used by:   a.example.com", "fingerprint: " + fingerprint(mineCert)} {
		if !strings.Contains(mine, want) {
			t.Errorf("mine lacks %q:\n%s", want, mine)
		}
	}
	if !strings.Contains(foreign, "signed by AOP_CA_CERT: no") || !strings.Contains(foreign, "used by:   none of the listed hostnames") {
		t.Errorf("foreign:\n%s", foreign)
	}
	for _, want := range []string{hostA + ": mine (enabled=true, status=active)", hostB + ": none", "cannot be discovered"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}

	delete(h.env, "AOP_CA_CERT")
	_, stdout, _ = h.run("leaf", "status")
	if !strings.Contains(stdout, "signed by AOP_CA_CERT: unknown") {
		t.Errorf("without AOP_CA_CERT:\n%s", stdout)
	}
}

// pruneHarness has hostA on "used", and "old" and "spare" unused.
func pruneHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	h.fake.addCert("used", h.ca.issue(t))
	h.fake.addCert("old", h.ca.issue(t))
	h.fake.addCert("spare", h.ca.issue(t))
	h.fake.setAssoc(hostA, "used", boolPtr(true))
	h.env["AOP_HOSTNAMES"] = hostA + "," + hostB
	return h
}

func deletes(h *harness) []string {
	var ids []string
	for _, r := range h.fake.recorded() {
		if r.method == http.MethodDelete {
			ids = append(ids, r.path[strings.LastIndex(r.path, "/")+1:])
		}
	}
	return ids
}

func TestLeafPruneRefusals(t *testing.T) {
	t.Run("no cert id", func(t *testing.T) {
		h := pruneHarness(t)
		code, _, stderr := h.run("leaf", "prune")
		if code != 2 || !strings.Contains(stderr, "aopctl leaf status") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
	})

	t.Run("no hostnames", func(t *testing.T) {
		h := pruneHarness(t)
		delete(h.env, "AOP_HOSTNAMES")
		code, _, stderr := h.run("leaf", "prune", "--cert-id", "old", "--yes")
		if code != 1 || !strings.Contains(stderr, "no hostnames") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if n := len(h.fake.recorded()); n != 0 {
			t.Errorf("sent %d requests", n)
		}
	})

	t.Run("in use", func(t *testing.T) {
		h := pruneHarness(t)
		code, _, stderr := h.run("leaf", "prune", "--cert-id", "used", "--yes")
		if code != 1 || !strings.Contains(stderr, "Refused used: still used by a.example.com") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if d := deletes(h); len(d) != 0 {
			t.Errorf("deleted %v", d)
		}
	})

	t.Run("other CA", func(t *testing.T) {
		h := pruneHarness(t)
		h.fake.addCert("foreign", newTestCA(t, 3650).issue(t))
		code, _, stderr := h.run("leaf", "prune", "--cert-id", "foreign", "--yes")
		if code != 1 || !strings.Contains(stderr, "Refused foreign: certificate foreign is not signed by AOP_CA_CERT") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if d := deletes(h); len(d) != 0 {
			t.Errorf("deleted %v", d)
		}
	})

	t.Run("not found", func(t *testing.T) {
		h := pruneHarness(t)
		code, _, stderr := h.run("leaf", "prune", "--cert-id", "missing", "--cert-id", "old", "--yes")
		if code != 1 || !strings.Contains(stderr, "Refused missing: not found") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if d := deletes(h); strings.Join(d, ",") != "old" {
			t.Errorf("deleted %v, want old only", d)
		}
	})

	t.Run("preflight association error", func(t *testing.T) {
		h := pruneHarness(t)
		h.fake.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/hostnames/"+hostB) {
				writeAPIError(w, http.StatusInternalServerError, 1000, "internal error")
				return true
			}
			return false
		}
		code, _, stderr := h.run("leaf", "prune", "--cert-id", "old", "--yes")
		if code != 1 || !strings.Contains(stderr, "read association for b.example.com") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if d := deletes(h); len(d) != 0 {
			t.Errorf("deleted %v", d)
		}
	})

	t.Run("only named ids", func(t *testing.T) {
		h := pruneHarness(t)
		code, _, stderr := h.run("leaf", "prune", "--cert-id", "old", "--yes")
		if code != 0 {
			t.Fatalf("exit %d; stderr:\n%s", code, stderr)
		}
		if d := deletes(h); strings.Join(d, ",") != "old" {
			t.Errorf("deleted %v, want old only", d)
		}
		if !strings.Contains(stderr, pruneWarning) {
			t.Errorf("preview lacks the hostname-scope warning:\n%s", stderr)
		}
		if !strings.Contains(stderr, "old  existing leaf, expires ") {
			t.Errorf("preview lacks the certificate:\n%s", stderr)
		}
	})
}

func TestLeafPruneChangeAfterPreview(t *testing.T) {
	// changeOnReread lets the first read of hostB through and handles the
	// second, which happens just before the DELETE.
	changeOnReread := func(h *harness, second func(w http.ResponseWriter) bool) {
		reads := 0
		h.fake.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/hostnames/"+hostB) {
				return false
			}
			reads++
			if reads == 2 {
				return second(w)
			}
			return false
		}
	}

	t.Run("now associated", func(t *testing.T) {
		h := pruneHarness(t)
		changeOnReread(h, func(http.ResponseWriter) bool {
			h.fake.assocs[hostB] = &fakeAssoc{certID: "old", enabled: boolPtr(true), statuses: []string{statusActive}}
			return false
		})
		code, _, stderr := h.run("leaf", "prune", "--cert-id", "old", "--yes")
		if d := deletes(h); len(d) != 0 {
			t.Fatalf("deleted %v after the certificate came into use", d)
		}
		if code != 1 || !strings.Contains(stderr, "Refused old: now used by b.example.com") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
	})

	t.Run("re-read fails", func(t *testing.T) {
		h := pruneHarness(t)
		changeOnReread(h, func(w http.ResponseWriter) bool {
			writeAPIError(w, http.StatusInternalServerError, 1000, "internal error")
			return true
		})
		code, _, stderr := h.run("leaf", "prune", "--cert-id", "old", "--yes")
		if d := deletes(h); len(d) != 0 {
			t.Fatalf("deleted %v after the re-read failed", d)
		}
		if code != 1 || !strings.Contains(stderr, "Failed old: read association for b.example.com") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
	})
}

func TestLeafPruneConfirmation(t *testing.T) {
	for _, tt := range []struct {
		answer string
		delete bool
	}{
		{"y\n", true},
		{"YES\n", true},
		{"n\n", false},
		{"\n", false},
		{"", false},
		{"yes please\n", false},
		// EOF before a newline aborts, whatever was typed.
		{"y", false},
		{"yes", false},
	} {
		t.Run(strconv.Quote(tt.answer), func(t *testing.T) {
			h := pruneHarness(t)
			tty := &fakeTTY{Reader: strings.NewReader(tt.answer)}
			h.openTTY = func() (io.ReadWriteCloser, error) { return tty, nil }
			code, _, stderr := h.run("leaf", "prune", "--cert-id", "old")
			if !strings.Contains(tty.prompt.String(), "Delete 1 certificate(s)? [y/N]") {
				t.Errorf("prompt = %q", tty.prompt.String())
			}
			d := deletes(h)
			if tt.delete {
				if code != 0 || strings.Join(d, ",") != "old" {
					t.Errorf("exit %d, deleted %v; stderr:\n%s", code, d, stderr)
				}
				return
			}
			if code != 1 || len(d) != 0 || !strings.Contains(stderr, "aborted") {
				t.Errorf("exit %d, deleted %v; stderr:\n%s", code, d, stderr)
			}
		})
	}

	t.Run("no terminal", func(t *testing.T) {
		h := pruneHarness(t)
		code, _, stderr := h.run("leaf", "prune", "--cert-id", "old")
		if code != 1 || !strings.Contains(stderr, "--yes") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if d := deletes(h); len(d) != 0 {
			t.Errorf("deleted %v", d)
		}
	})

	t.Run("yes skips the prompt", func(t *testing.T) {
		h := pruneHarness(t)
		h.openTTY = func() (io.ReadWriteCloser, error) {
			t.Error("opened the terminal despite --yes")
			return nil, io.EOF
		}
		code, _, stderr := h.run("leaf", "prune", "--cert-id", "old", "--yes")
		if code != 0 || strings.Join(deletes(h), ",") != "old" {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
	})
}

func TestLeafPruneCompletion(t *testing.T) {
	t.Run("pending then gone", func(t *testing.T) {
		h := pruneHarness(t)
		code, _, stderr := h.run("leaf", "prune", "--cert-id", "old", "--yes")
		if code != 0 || !strings.Contains(stderr, "Deleted old") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if n := h.fake.count(http.MethodGet, "/certificates/old"); n < 3 {
			t.Errorf("polled %d times, want polling until gone", n)
		}
	})

	t.Run("deletion timed out", func(t *testing.T) {
		h := pruneHarness(t)
		h.fake.deleteStatuses = []string{statusPendingDeletion, statusDeletionTimedOut}
		code, _, stderr := h.run("leaf", "prune", "--cert-id", "old", "--yes")
		if code != 1 || !strings.Contains(stderr, "Failed old: the delete failed at Cloudflare: status deletion_timed_out") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
	})

	t.Run("mixed results", func(t *testing.T) {
		h := pruneHarness(t)
		h.fake.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/old") {
				writeAPIError(w, http.StatusInternalServerError, 1000, "internal error")
				return true
			}
			return false
		}
		code, _, stderr := h.run("leaf", "prune", "--cert-id", "old", "--cert-id", "spare", "--yes")
		if code != 1 || !strings.Contains(stderr, "Failed old") || !strings.Contains(stderr, "Deleted spare") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if d := deletes(h); strings.Join(d, ",") != "old,spare" {
			t.Errorf("deleted %v, want old,spare", d)
		}
	})

	t.Run("already deleted", func(t *testing.T) {
		h := pruneHarness(t)
		h.fake.addCert("done", h.ca.issue(t), statusDeleted)
		code, _, stderr := h.run("leaf", "prune", "--cert-id", "done", "--yes")
		if code != 0 || !strings.Contains(stderr, "Already deleted: done") || len(deletes(h)) != 0 {
			t.Errorf("exit %d, deleted %v; stderr:\n%s", code, deletes(h), stderr)
		}
	})

	for _, tt := range []struct {
		name      string
		statuses  []string
		waitLimit int
		code      int
		want      string
	}{
		{"already pending, then gone", []string{statusPendingDeletion, statusPendingDeletion, "gone"}, 0, 0, "Deleted pending"},
		{"already pending, then timed out", []string{statusPendingDeletion, statusDeletionTimedOut}, 0, 1, "status deletion_timed_out"},
		{"already pending, budget runs out", []string{statusPendingDeletion}, 3, 1, "timed out waiting for the delete to finish: last status pending_deletion"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := pruneHarness(t)
			h.fake.addCert("pending", h.ca.issue(t), tt.statuses...)
			h.waitLimit = tt.waitLimit
			// No --yes and no terminal: a certificate that needs no DELETE
			// needs no confirmation.
			code, _, stderr := h.run("leaf", "prune", "--cert-id", "pending")
			if code != tt.code || !strings.Contains(stderr, tt.want) {
				t.Errorf("exit %d; stderr:\n%s", code, stderr)
			}
			if d := deletes(h); len(d) != 0 {
				t.Errorf("deleted %v", d)
			}
		})
	}
}
