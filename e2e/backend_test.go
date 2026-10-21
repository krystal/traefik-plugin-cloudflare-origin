//go:build e2e

package e2e

import (
	"crypto/sha1" //nolint:gosec // RFC 6455 defines Sec-WebSocket-Accept with SHA-1.
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const testIDHeader = "X-Test-Id"

// backend is an HTTP echo server that records the headers of every request
// it receives, keyed by the X-Test-Id header the client sets.
type backend struct {
	server *httptest.Server
	mu     sync.Mutex
	seen   map[string]http.Header
}

func newBackend(t *testing.T) *backend {
	t.Helper()
	b := &backend{seen: map[string]http.Header{}}
	b.server = httptest.NewServer(http.HandlerFunc(b.serveHTTP))
	t.Cleanup(b.server.Close)
	return b
}

func (b *backend) request(id string) (http.Header, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	h, ok := b.seen[id]
	return h, ok
}

func (b *backend) serveHTTP(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	b.seen[r.Header.Get(testIDHeader)] = r.Header.Clone()
	b.mu.Unlock()

	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		w.WriteHeader(http.StatusOK)
		return
	}

	conn, rw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()
	sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) //nolint:gosec // See import.
	fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
		base64.StdEncoding.EncodeToString(sum[:]))
	if err := rw.Flush(); err != nil {
		return
	}
	// Echo raw bytes until the client closes; the test only checks that
	// data round-trips through the upgraded connection.
	_, _ = io.Copy(conn, rw.Reader)
}
