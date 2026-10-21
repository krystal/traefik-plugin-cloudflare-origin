//go:build e2e

// Package e2e runs the plugin inside a real Traefik binary, loaded through
// Yaegi from plugins-local exactly as the shipped files would be.
package e2e

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	clientIP   = "203.0.113.7"
	loopbackV4 = "127.0.0.1"
	loopbackV6 = "::1"
)

var nextID atomic.Int64

// call describes one client request. The client dials addr, sends sni
// (defaulting to host) in the handshake and host in the Host header.
type call struct {
	addr string
	host string
	sni  string
	cert *tls.Certificate
	// forceCert is sent via GetClientCertificate, which bypasses Go's check
	// that the certificate matches the server's acceptable CAs.
	forceCert *tls.Certificate
	header    map[string]string
	h2        bool
	sessions  tls.ClientSessionCache
}

type result struct {
	status int
	body   string
	proto  int
	tls    *tls.ConnectionState
	seen   http.Header // nil when the request never reached the backend
}

func (e *env) tlsConfig(c call) *tls.Config {
	cfg := &tls.Config{ServerName: c.sni, ClientSessionCache: c.sessions, MinVersion: tls.VersionTLS12}
	if cfg.ServerName == "" {
		cfg.ServerName = c.host
	}
	if c.cert != nil {
		cfg.Certificates = []tls.Certificate{*c.cert}
	}
	if c.forceCert != nil {
		forced := c.forceCert
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return forced, nil
		}
	}
	return cfg
}

func (e *env) try(c call) (result, error) {
	id := fmt.Sprintf("req-%d", nextID.Add(1))
	client := e.client(c.addr, e.tlsConfig(c), c.h2)
	defer client.CloseIdleConnections()

	req, err := http.NewRequest(http.MethodGet, "https://"+c.host+"/", nil)
	if err != nil {
		return result{}, err
	}
	for k, v := range c.header {
		req.Header[k] = []string{v}
	}
	req.Header.Set(testIDHeader, id)

	resp, err := client.Do(req)
	if err != nil {
		return result{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return result{}, err
	}
	r := result{status: resp.StatusCode, body: string(body), proto: resp.ProtoMajor, tls: resp.TLS}
	r.seen, _ = e.backend.request(id)
	return r, nil
}

func (e *env) do(t *testing.T, c call) result {
	t.Helper()
	r, err := e.try(c)
	if err != nil {
		t.Fatalf("request to %s (Host %s): %v", c.addr, c.host, err)
	}
	return r
}

func cf(ip string) map[string]string {
	return map[string]string{"Cf-Connecting-Ip": ip}
}

// assertDelivered checks what the backend received. An empty cfIP means
// Cf-Connecting-Ip must be absent.
func assertDelivered(t *testing.T, r result, xff, realIP, cfIP string) {
	t.Helper()
	if r.status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", r.status, r.body)
	}
	if r.seen == nil {
		t.Fatal("request did not reach the backend")
	}
	if got := strings.Join(r.seen.Values("X-Forwarded-For"), ", "); got != xff {
		t.Errorf("X-Forwarded-For = %q, want %q", got, xff)
	}
	if got := strings.Join(r.seen.Values("X-Real-Ip"), ", "); got != realIP {
		t.Errorf("X-Real-Ip = %q, want %q", got, realIP)
	}
	if got := strings.Join(r.seen.Values("Cf-Connecting-Ip"), ", "); got != cfIP {
		t.Errorf("Cf-Connecting-Ip = %q, want %q", got, cfIP)
	}
}

func assertRejected(t *testing.T, r result, status int) {
	t.Helper()
	if r.status != status {
		t.Fatalf("status = %d, want %d (body %q)", r.status, status, r.body)
	}
	if r.seen != nil {
		t.Fatalf("rejected request reached the backend with headers %v", r.seen)
	}
}

func TestTraefik(t *testing.T) {
	e := startTraefik(t, false)
	c := e.certs

	t.Run("E1 verified rewrite replaces junk forwarding headers over HTTP/1.1", func(t *testing.T) {
		testVerifiedRewriteHTTP1(t, e)
	})

	t.Run("E2 verified IPv6 client value over HTTP/2", func(t *testing.T) {
		r := e.do(t, call{
			addr: e.addr4, host: "protected.test", cert: &c.cfLeaf, h2: true,
			header: cf("2001:DB8:0::7"),
		})
		if r.proto != 2 {
			t.Fatalf("protocol = HTTP/%d, want HTTP/2", r.proto)
		}
		assertDelivered(t, r, "2001:db8::7", "2001:db8::7", "2001:db8::7")
	})

	t.Run("E3 resumed TLS session keeps verified chains", func(t *testing.T) {
		sessions := tls.NewLRUClientSessionCache(4)
		first := e.do(t, call{
			addr: e.addr4, host: "protected.test", cert: &c.cfLeaf, sessions: sessions, header: cf(clientIP),
		})
		assertDelivered(t, first, clientIP, clientIP, clientIP)
		if first.tls.DidResume {
			t.Fatal("first connection resumed a session")
		}

		second := e.do(t, call{
			addr: e.addr4, host: "protected.test", cert: &c.cfLeaf, sessions: sessions, header: cf("203.0.113.8"),
		})
		if !second.tls.DidResume {
			t.Fatal("second connection did not resume the session")
		}
		assertDelivered(t, second, "203.0.113.8", "203.0.113.8", "203.0.113.8")
	})

	t.Run("E4 client IP headers are stripped", func(t *testing.T) {
		spoofed := map[string]string{
			"Cf-Connecting-Ip":   "192.0.2.10",
			"True-Client-Ip":     "192.0.2.11",
			"Cf-Connecting-Ipv6": "2001:db8::11",
			"Cf-Pseudo-Ipv4":     "240.0.0.11",
			"Cf_Connecting_Ip":   "192.0.2.12",
			"True_Client_Ip":     "192.0.2.13",
			"cf_connecting_ipv6": "2001:db8::13",
			"cf_pseudo_ipv4":     "240.0.0.13",
			"X-Forwarded-For":    "192.0.2.14",
		}
		assertStripped := func(t *testing.T, r result) {
			t.Helper()
			for key := range r.seen {
				switch http.CanonicalHeaderKey(strings.ReplaceAll(key, "_", "-")) {
				case "True-Client-Ip", "Cf-Connecting-Ipv6", "Cf-Pseudo-Ipv4":
					t.Errorf("header %q reached the backend", key)
				case "Cf-Connecting-Ip":
					if key != "Cf-Connecting-Ip" {
						t.Errorf("header %q reached the backend", key)
					}
				}
			}
		}

		t.Run("unverified", func(t *testing.T) {
			r := e.do(t, call{addr: e.addr4, host: "open.test", header: spoofed})
			assertDelivered(t, r, loopbackV4, loopbackV4, "")
			assertStripped(t, r)
		})
		t.Run("verified", func(t *testing.T) {
			r := e.do(t, call{addr: e.addr4, host: "open.test", cert: &c.cfLeaf, header: spoofed})
			assertDelivered(t, r, "192.0.2.10", "192.0.2.10", "192.0.2.10")
			assertStripped(t, r)
		})
	})

	t.Run("E5 protected host allows direct CIDR and denies other peers", func(t *testing.T) {
		t.Run("IPv4 loopback denied", func(t *testing.T) {
			r := e.do(t, call{addr: e.addr4, host: "protected.test", header: cf(loopbackV6)})
			assertRejected(t, r, http.StatusForbidden)
			if r.body != "Forbidden\n" {
				t.Errorf("body = %q, want %q", r.body, "Forbidden\n")
			}
		})
		t.Run("IPv6 loopback allowed", func(t *testing.T) {
			e.requireIPv6(t)
			r := e.do(t, call{addr: e.addr6, host: "protected.test", header: cf(clientIP)})
			assertDelivered(t, r, loopbackV6, loopbackV6, "")
		})
	})

	t.Run("E6 Host decides protection, not SNI", func(t *testing.T) {
		t.Run("open SNI with protected Host", func(t *testing.T) {
			r := e.do(t, call{addr: e.addr4, host: "protected.test", sni: "open.test"})
			assertRejected(t, r, http.StatusForbidden)
		})
		t.Run("SNI with a different TLS option", func(t *testing.T) {
			r := e.do(t, call{addr: e.addr4, host: "protected.test", sni: "other.test"})
			assertRejected(t, r, http.StatusMisdirectedRequest)
		})
	})

	t.Run("E7 certificate from another client CA is not trusted", func(t *testing.T) {
		t.Run("open host under other TLS option is not rewritten", func(t *testing.T) {
			r := e.do(t, call{addr: e.addr4, host: "other.test", cert: &c.otherLeaf, header: cf(clientIP)})
			assertDelivered(t, r, loopbackV4, loopbackV4, "")
		})
		t.Run("protected host trusting both CAs rejects other cert", func(t *testing.T) {
			r := e.do(t, call{addr: e.addr4, host: "both.test", cert: &c.otherLeaf, header: cf(clientIP)})
			assertRejected(t, r, http.StatusForbidden)
		})
		t.Run("protected host trusting both CAs accepts AOP cert", func(t *testing.T) {
			r := e.do(t, call{addr: e.addr4, host: "both.test", cert: &c.cfLeaf, header: cf(clientIP)})
			assertDelivered(t, r, clientIP, clientIP, clientIP)
		})
	})

	t.Run("E8 rogue CA certificate fails the handshake", func(t *testing.T) {
		r, err := e.try(call{addr: e.addr4, host: "protected.test", forceCert: &c.rogueLeaf, header: cf(clientIP)})
		if err == nil {
			t.Fatalf("got HTTP %d, want a TLS error", r.status)
		}
		if !strings.Contains(err.Error(), "tls: ") {
			t.Fatalf("error = %v, want a TLS alert", err)
		}
	})

	t.Run("E9 ipAllowList sees the restored IP", func(t *testing.T) {
		t.Run("restored IP in range", func(t *testing.T) {
			r := e.do(t, call{addr: e.addr4, host: "allow.test", cert: &c.cfLeaf, header: cf(clientIP)})
			assertDelivered(t, r, clientIP, clientIP, clientIP)
		})
		t.Run("restored IP out of range", func(t *testing.T) {
			r := e.do(t, call{addr: e.addr4, host: "allow.test", cert: &c.cfLeaf, header: cf("198.51.100.7")})
			assertRejected(t, r, http.StatusForbidden)
		})
		t.Run("unverified spoof of in-range IP", func(t *testing.T) {
			r := e.do(t, call{addr: e.addr4, host: "allow.test", header: cf(clientIP)})
			assertRejected(t, r, http.StatusForbidden)
		})
	})

	t.Run("E10 verified rewrite from an IPv6 peer", func(t *testing.T) {
		e.requireIPv6(t)
		r := e.do(t, call{addr: e.addr6, host: "open.test", cert: &c.cfLeaf, header: cf(clientIP)})
		assertDelivered(t, r, clientIP, clientIP, clientIP)

		r = e.do(t, call{addr: e.addr6, host: "open.test", header: cf(clientIP)})
		assertDelivered(t, r, loopbackV6, loopbackV6, "")
	})

	t.Run("E11 WebSocket upgrade", func(t *testing.T) {
		testWebSocket(t, e)
	})

	t.Run("E12 chained instances", func(t *testing.T) {
		t.Run("identical pins rewrite once", func(t *testing.T) {
			r := e.do(t, call{addr: e.addr4, host: "same.test", cert: &c.cfLeaf, header: cf(clientIP)})
			assertDelivered(t, r, clientIP, clientIP, clientIP)
		})
		t.Run("identical pins deny unverified outside peer", func(t *testing.T) {
			r := e.do(t, call{addr: e.addr4, host: "same.test", header: cf(loopbackV6)})
			assertRejected(t, r, http.StatusForbidden)
		})
		t.Run("router leaf pin accepts its leaf", func(t *testing.T) {
			r := e.do(t, call{addr: e.addr4, host: "leaf.test", cert: &c.cfLeaf, header: cf("192.0.2.10")})
			assertDelivered(t, r, "192.0.2.10", "192.0.2.10", "192.0.2.10")
		})
		t.Run("router leaf pin denies other leaf claiming an allowlisted IP", func(t *testing.T) {
			r := e.do(t, call{addr: e.addr4, host: "leaf.test", cert: &c.cfOtherLeaf, header: cf("192.0.2.10")})
			assertRejected(t, r, http.StatusForbidden)
		})
		t.Run("router leaf pin reverts rewrite for allowlisted peer", func(t *testing.T) {
			e.requireIPv6(t)
			r := e.do(t, call{addr: e.addr6, host: "leaf.test", cert: &c.cfOtherLeaf, header: cf(clientIP)})
			assertDelivered(t, r, loopbackV6, loopbackV6, "")
		})
		t.Run("router pin restores from original header after entrypoint rejects", func(t *testing.T) {
			r := e.do(t, call{addr: e.addr4, host: "reverse.test", cert: &c.otherLeaf, header: cf(clientIP)})
			assertDelivered(t, r, clientIP, clientIP, clientIP)
		})
	})

	t.Run("E13 allowMissingClientIP default and explicit false", func(t *testing.T) {
		t.Run("default passes verified request with edge IP", func(t *testing.T) {
			r := e.do(t, call{addr: e.addr4, host: "open.test", cert: &c.cfLeaf})
			assertDelivered(t, r, loopbackV4, loopbackV4, "")
		})
		t.Run("false rejects verified request", func(t *testing.T) {
			r := e.do(t, call{addr: e.addr4, host: "strict.test", cert: &c.cfLeaf})
			assertRejected(t, r, http.StatusForbidden)
		})
		t.Run("false passes verified request with client IP", func(t *testing.T) {
			r := e.do(t, call{addr: e.addr4, host: "strict.test", cert: &c.cfLeaf, header: cf(clientIP)})
			assertDelivered(t, r, clientIP, clientIP, clientIP)
		})
	})
}

func TestTraefikFastProxy(t *testing.T) {
	e := startTraefik(t, true)

	t.Run("E1 verified rewrite replaces junk forwarding headers over HTTP/1.1", func(t *testing.T) {
		testVerifiedRewriteHTTP1(t, e)
	})
	t.Run("E11 WebSocket upgrade", func(t *testing.T) {
		testWebSocket(t, e)
	})
}

func testVerifiedRewriteHTTP1(t *testing.T, e *env) {
	t.Helper()
	r := e.do(t, call{
		addr: e.addr4, host: "protected.test", cert: &e.certs.cfLeaf,
		header: map[string]string{
			"Cf-Connecting-Ip": clientIP,
			"X-Forwarded-For":  "192.0.2.66, 192.0.2.67",
			"X-Real-Ip":        "192.0.2.68",
		},
	})
	if r.proto != 1 {
		t.Fatalf("protocol = HTTP/%d, want HTTP/1.1", r.proto)
	}
	assertDelivered(t, r, clientIP, clientIP, clientIP)
	e.assertProxy(t, r.seen)
}

func testWebSocket(t *testing.T, e *env) {
	t.Helper()
	cfg := e.tlsConfig(call{host: "open.test", cert: &e.certs.cfLeaf})
	cfg.RootCAs = e.certs.serverPool
	cfg.NextProtos = []string{"http/1.1"}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dialer := &tls.Dialer{NetDialer: &net.Dialer{}, Config: cfg}
	conn, err := dialer.DialContext(ctx, "tcp", e.addr4)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	id := fmt.Sprintf("ws-%d", nextID.Add(1))
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: open.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"+
		"Cf-Connecting-Ip: %s\r\nX-Forwarded-For: 192.0.2.66\r\n%s: %s\r\n\r\n", clientIP, testIDHeader, id)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}

	seen, ok := e.backend.request(id)
	if !ok {
		t.Fatal("upgrade request did not reach the backend")
	}
	if got := strings.Join(seen.Values("X-Forwarded-For"), ", "); got != clientIP {
		t.Errorf("X-Forwarded-For on upgrade = %q, want %q", got, clientIP)
	}
	if got := seen.Get("X-Real-Ip"); got != clientIP {
		t.Errorf("X-Real-Ip on upgrade = %q, want %q", got, clientIP)
	}
	e.assertProxy(t, seen)

	payload := []byte("ping through the upgraded connection")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(br, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(echo) != string(payload) {
		t.Fatalf("echo = %q, want %q", echo, payload)
	}
}
