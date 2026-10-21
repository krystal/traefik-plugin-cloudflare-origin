package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) *cfClient {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &cfClient{baseURL: srv.URL, token: testToken, zoneID: testZone, http: &http.Client{Timeout: requestTimeout}}
}

func writeRaw(w http.ResponseWriter, status int, contentType, body string) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func TestClientSendsBearerToken(t *testing.T) {
	var auth, agent string
	cf := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		auth, agent = r.Header.Get("Authorization"), r.Header.Get("User-Agent")
		writeEnvelope(w, http.StatusOK, []any{}, nil)
	})
	if _, err := cf.listCerts(context.Background()); err != nil {
		t.Fatalf("listCerts: %v", err)
	}
	if auth != "Bearer "+testToken {
		t.Errorf("Authorization = %q", auth)
	}
	if agent != userAgent {
		t.Errorf("User-Agent = %q", agent)
	}
}

func TestClientErrors(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    string
	}{
		{
			name: "non-2xx with success true",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeRaw(w, http.StatusBadGateway, "application/json", `{"success":true,"errors":[],"messages":[],"result":[]}`)
			},
			want: "HTTP 502",
		},
		{
			name: "2xx with success false",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeRaw(w, http.StatusOK, "application/json", `{"success":false,"errors":[{"code":1001,"message":"nope"}],"messages":[],"result":null}`)
			},
			want: "HTTP 200 (code 1001): request unsuccessful: nope",
		},
		{
			name: "malformed JSON",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeRaw(w, http.StatusOK, "application/json", `{"success":true,"result":[`)
			},
			want: `HTTP 200: undecodable response (content type "application/json")`,
		},
		{
			name: "non-JSON body",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeRaw(w, http.StatusBadGateway, "text/html", "<html>upstream secret page</html>")
			},
			want: `HTTP 502: undecodable response (content type "text/html")`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cf := newTestClient(t, tt.handler)
			_, err := cf.listCerts(context.Background())
			if err == nil {
				t.Fatal("listCerts succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %q, want it to contain %q", err, tt.want)
			}
			if !strings.HasPrefix(err.Error(), "GET /zones/{zone}/origin_tls_client_auth/hostnames/certificates") {
				t.Errorf("err does not name the redacted path: %q", err)
			}
			if strings.Contains(err.Error(), "secret page") {
				t.Errorf("err contains the response body: %q", err)
			}
		})
	}
}

// TestResponseClassification checks which failed responses polling retries
// and which count as a Cloudflare 404.
func TestResponseClassification(t *testing.T) {
	tests := []struct {
		name      string
		handler   http.HandlerFunc
		want      string
		transient bool
		notFound  bool
	}{
		{
			name:      "connection reset",
			handler:   func(w http.ResponseWriter, _ *http.Request) { resetConnection(t, w) },
			transient: true,
		},
		{
			name:      "body cut off",
			handler:   func(w http.ResponseWriter, _ *http.Request) { writeCutOff(t, w, http.StatusOK) },
			want:      "HTTP 200: unexpected EOF",
			transient: true,
		},
		{
			name: "no success field",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeRaw(w, http.StatusOK, "application/json", `{"result":{"id":"x"}}`)
			},
			want: `HTTP 200: undecodable response (content type "application/json")`,
		},
		{
			name: "too large",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				body := `{"success":true,"errors":[],"messages":[],"result":{}}`
				writeRaw(w, http.StatusOK, "application/json", body+strings.Repeat(" ", maxResponseBytes+1-len(body)))
			},
			want: `HTTP 200: response too large (content type "application/json")`,
		},
		{
			name: "non-JSON 503",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeRaw(w, http.StatusServiceUnavailable, "text/html", "<html>busy</html>")
			},
			want:      "HTTP 503: undecodable response",
			transient: true,
		},
		{
			name: "non-JSON 404",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeRaw(w, http.StatusNotFound, "text/html", "<html>Not Found</html>")
			},
			want: "HTTP 404: undecodable response",
		},
		{
			name: "Cloudflare 404",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeAPIError(w, http.StatusNotFound, 1551, "certificate not found")
			},
			want:     "HTTP 404 (code 1551): certificate not found",
			notFound: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cf := newTestClient(t, tt.handler)
			_, err := cf.getCert(context.Background(), "x")
			if err == nil {
				t.Fatal("getCert succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tt.want) || strings.Contains(err.Error(), testZone) {
				t.Errorf("err = %q, want it to contain %q and not the zone ID", err, tt.want)
			}
			if got := isTransient(err); got != tt.transient {
				t.Errorf("isTransient = %v, want %v", got, tt.transient)
			}
			if got := isNotFound(err); got != tt.notFound {
				t.Errorf("isNotFound = %v, want %v", got, tt.notFound)
			}
		})
	}
}

// TestErrorsRedactSecrets uses a server that echoes the request body, the
// token and the zone ID back in the envelope's messages.
func TestErrorsRedactSecrets(t *testing.T) {
	ca := newTestCA(t, 3650)
	leaf, key, err := createLeaf(ca.cert, ca.key, "leaf", keyTypeECP256, 30, time.Now())
	if err != nil {
		t.Fatalf("createLeaf: %v", err)
	}
	keyPEM, err := encodeKeyPEM(key)
	if err != nil {
		t.Fatalf("encodeKeyPEM: %v", err)
	}

	cf := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		zone := strings.Split(r.URL.Path, "/")[2]
		echo := fmt.Sprintf("body=%s token=%s zone=%s", body, token, zone)
		// A cut-off copy has no END line, and a bare copy has no PEM armor.
		cut := string(body[:len(body)-60])
		bare := strings.Join(strings.Split(keyPEM, "\n")[1:3], "")
		writeEnvelope(w, http.StatusBadRequest, nil, map[string]any{
			"success":  false,
			"errors":   []any{map[string]any{"code": 1000, "message": echo}},
			"messages": []any{cut, map[string]any{"code": 0, "message": "key " + bare + " zone" + zone + "token" + token}},
		})
	})
	_, err = cf.uploadCert(context.Background(), encodeCertPEM(leaf), keyPEM)
	if err == nil {
		t.Fatal("uploadCert succeeded, want an error")
	}
	msg := err.Error()

	for _, leak := range []string{testZone, "suffix7", "AAAA", "PRIVATE KEY", "BEGIN"} {
		if strings.Contains(msg, leak) {
			t.Errorf("error contains %q: %s", leak, msg)
		}
	}
	keyBody := strings.Join(strings.Split(strings.TrimSpace(keyPEM), "\n")[1:], "")
	for i := 0; i+12 <= len(keyBody); i++ {
		if strings.Contains(msg, keyBody[i:i+12]) {
			t.Fatalf("error contains part of the key (%q): %s", keyBody[i:i+12], msg)
		}
	}
	if !strings.Contains(msg, "[redacted PEM]") || !strings.Contains(msg, "token=[redacted]") || !strings.Contains(msg, "zone=[redacted]") {
		t.Errorf("error lacks the redaction markers: %s", msg)
	}
	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err is %T, want *apiError", err)
	}
	for _, m := range apiErr.messages {
		if len(m) > maxMessageBytes {
			t.Errorf("message has %d bytes, want at most %d", len(m), maxMessageBytes)
		}
	}
}

func TestErrorsKeepBenignMessages(t *testing.T) {
	cf := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		writeAPIError(w, http.StatusBadRequest, 1400, "missing leaf certificate")
	})
	_, err := cf.uploadCert(context.Background(), "cert", "key")
	if err == nil || !strings.Contains(err.Error(), "(code 1400): missing leaf certificate") {
		t.Errorf("err = %v", err)
	}
	var apiErr *apiError
	if !errors.As(err, &apiErr) || !apiErr.decoded {
		t.Errorf("err is not a decoded API error: %#v", err)
	}
}

func TestSanitizeOrder(t *testing.T) {
	cf := &cfClient{token: testToken, zoneID: testZone}
	got := cf.sanitize("Bearer " + testToken + "; zone " + testZone + "; ok")
	if want := "Bearer [redacted]; zone [redacted]; ok"; got != want {
		t.Errorf("sanitize = %q, want %q", got, want)
	}
}

func TestPagination(t *testing.T) {
	h := newHarness(t)
	h.fake.perPage = 3
	for i := 1; i <= 10; i++ {
		h.fake.addCert(fmt.Sprintf("cert-%02d", i), h.ca.issue(t))
	}

	code, stdout, stderr := h.run("leaf", "status")
	if code != 0 {
		t.Fatalf("status: exit %d; stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stdout, "Certificates (10 of 10)") || !strings.Contains(stdout, "cert-10") {
		t.Errorf("status misses later pages:\n%s", stdout)
	}

	// cert-10 is alone on page 4, and it fills the last slot.
	code, _, stderr = h.run("leaf", "issue", "--hostname", "app.example.com")
	if code != 1 || !strings.Contains(stderr, "the zone has 10 hostname certificates") {
		t.Errorf("issue: exit %d; stderr:\n%s", code, stderr)
	}
	if n := h.fake.count(http.MethodPost, "/certificates"); n != 0 {
		t.Errorf("sent %d uploads, want none", n)
	}
	var pages []string
	for _, r := range h.fake.recorded() {
		if r.method == http.MethodGet && strings.HasSuffix(r.path, "/certificates") {
			pages = append(pages, r.query)
		}
	}
	if got := strings.Join(pages, " "); got != "page=1 page=2 page=3 page=4 page=1 page=2 page=3 page=4" {
		t.Errorf("list requests = %s", got)
	}
}

func TestStalledRequest(t *testing.T) {
	received := make(chan struct{})
	cf := newTestClient(t, func(_ http.ResponseWriter, r *http.Request) {
		close(received)
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		_, err := cf.listCerts(ctx)
		errc <- err
	}()

	select {
	case <-received:
	case <-time.After(10 * time.Second):
		t.Fatal("the server did not receive the request")
	}
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
		if strings.Contains(err.Error(), testZone) {
			t.Errorf("err contains the zone ID: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the request did not return after its context was cancelled")
	}
}

func TestAPIMessagesTolerateShapes(t *testing.T) {
	var env envelope
	data := `{"success":false,"errors":[{"code":7,"message":"a"},"b",42],"messages":{"odd":true},"result":null}`
	if err := json.Unmarshal([]byte(data), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(env.Errors) != 2 || env.Errors[0].Code != 7 || env.Errors[1].Message != "b" {
		t.Errorf("errors = %+v", env.Errors)
	}
}
