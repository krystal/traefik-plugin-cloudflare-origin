package traefik_plugin_cloudflare_origin

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Only Raw is read by the plugin, so fake DER bytes are enough.
var (
	aopRoot      = &x509.Certificate{Raw: []byte("aop root ca")}
	aopInter     = &x509.Certificate{Raw: []byte("aop intermediate ca")}
	aopLeaf      = &x509.Certificate{Raw: []byte("aop leaf")}
	aopOtherLeaf = &x509.Certificate{Raw: []byte("aop other leaf")}
	otherRoot    = &x509.Certificate{Raw: []byte("other root ca")}
	otherLeaf    = &x509.Certificate{Raw: []byte("other leaf")}
)

const (
	protectedHost = "protected.example.com"
	openHost      = "open.example.com"
	edgePeer      = "198.51.100.10:44321"
	edgeIP        = "198.51.100.10"
	outsidePeer   = "203.0.113.50:40000"
)

func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func verifiedState(chains ...[]*x509.Certificate) *tls.ConnectionState {
	state := &tls.ConnectionState{HandshakeComplete: true, ServerName: protectedHost}
	for _, chain := range chains {
		state.PeerCertificates = chain
		state.VerifiedChains = append(state.VerifiedChains, chain)
	}
	return state
}

func aopChain() *tls.ConnectionState {
	return verifiedState([]*x509.Certificate{aopLeaf, aopInter, aopRoot})
}

func baseConfig() *Config {
	cfg := CreateConfig()
	cfg.ClientCertFingerprints = []string{fingerprint(aopRoot)}
	cfg.ProtectedHosts = []string{protectedHost}
	cfg.DirectAccessCIDRs = []string{"192.0.2.0/24", "2001:db8:1::/48", "198.51.100.200"}
	return cfg
}

// backend records what reached the next handler.
type backend struct {
	called     bool
	remoteAddr string
	header     http.Header
}

func (b *backend) handler() http.Handler {
	return http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		b.called = true
		b.remoteAddr = req.RemoteAddr
		b.header = req.Header.Clone()
	})
}

func mustNew(t *testing.T, next http.Handler, cfg *Config) http.Handler {
	t.Helper()
	h, err := New(context.Background(), next, cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

type request struct {
	host       string
	remoteAddr string
	tls        *tls.ConnectionState
	header     map[string][]string
}

func serve(h http.Handler, r request) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = r.host
	req.RemoteAddr = r.remoteAddr
	req.TLS = r.tls
	for k, v := range r.header {
		req.Header[k] = v
	}
	if req.Header.Get(xRealIP) == "" {
		// Traefik's forwardedheaders middleware sets X-Real-Ip to the peer.
		host := r.remoteAddr
		if i := strings.LastIndex(host, ":"); i >= 0 {
			host = strings.Trim(host[:i], "[]")
		}
		req.Header.Set(xRealIP, host)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// expect describes the outcome of one request. An empty cfIP means the
// backend must not receive Cf-Connecting-Ip.
type expect struct {
	status     int
	remoteAddr string
	realIP     string
	cfIP       string
}

func assertResult(t *testing.T, rec *httptest.ResponseRecorder, b *backend, want expect) {
	t.Helper()
	if rec.Code != want.status {
		t.Fatalf("status = %d, want %d", rec.Code, want.status)
	}
	if want.status == http.StatusForbidden {
		if b.called {
			t.Fatal("backend was called for a rejected request")
		}
		if body := rec.Body.String(); body != "Forbidden\n" {
			t.Fatalf("body = %q, want %q", body, "Forbidden\n")
		}
		return
	}
	if !b.called {
		t.Fatal("backend was not called")
	}
	if b.remoteAddr != want.remoteAddr {
		t.Errorf("RemoteAddr = %q, want %q", b.remoteAddr, want.remoteAddr)
	}
	if got := b.header.Values(xRealIP); len(got) != 1 || got[0] != want.realIP {
		t.Errorf("X-Real-Ip = %q, want [%q]", got, want.realIP)
	}
	got := b.header.Values(cfConnectingIP)
	switch {
	case want.cfIP == "" && len(got) != 0:
		t.Errorf("Cf-Connecting-Ip = %q, want absent", got)
	case want.cfIP != "" && (len(got) != 1 || got[0] != want.cfIP):
		t.Errorf("Cf-Connecting-Ip = %q, want [%q]", got, want.cfIP)
	}
}

func TestCreateConfigDefaults(t *testing.T) {
	if !CreateConfig().AllowMissingClientIP {
		t.Fatal("AllowMissingClientIP defaults to false, want true")
	}
}

// U1
func TestUnverifiedClientIPIsStripped(t *testing.T) {
	tests := []struct {
		name string
		tls  *tls.ConnectionState
		host string
	}{
		{"plain HTTP", nil, openHost},
		{"TLS without client cert", &tls.ConnectionState{HandshakeComplete: true}, openHost},
		{"TLS without client cert on protected host from direct CIDR", &tls.ConnectionState{}, protectedHost},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &backend{}
			h := mustNew(t, b.handler(), baseConfig())
			peer := edgePeer
			if tt.host == protectedHost {
				peer = "192.0.2.10:5555"
			}
			rec := serve(h, request{
				host: tt.host, remoteAddr: peer, tls: tt.tls,
				header: map[string][]string{cfConnectingIP: {"192.0.2.99"}},
			})
			ip := strings.Split(peer, ":")[0]
			assertResult(t, rec, b, expect{status: http.StatusOK, remoteAddr: peer, realIP: ip})
		})
	}
}

// Traefik keeps X-Real-Ip from peers in forwardedHeaders.trustedIPs; the
// plugin must pass it through on requests it does not rewrite.
func TestTrustedProxyRealIPIsKept(t *testing.T) {
	b := &backend{}
	h := mustNew(t, b.handler(), baseConfig())
	rec := serve(h, request{
		host: openHost, remoteAddr: edgePeer,
		header: map[string][]string{xRealIP: {"203.0.113.9"}, cfConnectingIP: {"192.0.2.99"}},
	})
	assertResult(t, rec, b, expect{status: http.StatusOK, remoteAddr: edgePeer, realIP: "203.0.113.9"})
}

// U2
func TestVerifiedClientIPIsRestored(t *testing.T) {
	tests := []struct {
		name       string
		peer       string
		cfIP       string
		remoteAddr string
		normalised string
	}{
		{"IPv4", edgePeer, "203.0.113.7", "203.0.113.7:44321", "203.0.113.7"},
		{"IPv6 normalised", edgePeer, "2001:DB8:0::7", "[2001:db8::7]:44321", "2001:db8::7"},
		{"IPv6 peer", "[2001:db8:ffff::1]:443", "203.0.113.7", "203.0.113.7:443", "203.0.113.7"},
		{"IPv4-mapped value", edgePeer, "::ffff:203.0.113.7", "203.0.113.7:44321", "203.0.113.7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &backend{}
			h := mustNew(t, b.handler(), baseConfig())
			rec := serve(h, request{
				host: protectedHost, remoteAddr: tt.peer, tls: aopChain(),
				header: map[string][]string{cfConnectingIP: {tt.cfIP}},
			})
			assertResult(t, rec, b, expect{
				status: http.StatusOK, remoteAddr: tt.remoteAddr, realIP: tt.normalised, cfIP: tt.normalised,
			})
		})
	}
}

// U3
func TestVerifiedWithoutUsableClientIP(t *testing.T) {
	values := []struct {
		name   string
		values []string
	}{
		{"missing", nil},
		{"empty", []string{""}},
		{"invalid", []string{"not-an-ip"}},
		{"duplicate", []string{"203.0.113.7", "203.0.113.8"}},
		{"comma list", []string{"203.0.113.7, 203.0.113.8"}},
		{"zoned", []string{"fe80::1%eth0"}},
	}
	for _, v := range values {
		for _, host := range []string{protectedHost, openHost} {
			t.Run(v.name+" allowed on "+host, func(t *testing.T) {
				b := &backend{}
				h := mustNew(t, b.handler(), baseConfig())
				header := map[string][]string{}
				if v.values != nil {
					header[cfConnectingIP] = v.values
				}
				rec := serve(h, request{host: host, remoteAddr: edgePeer, tls: aopChain(), header: header})
				assertResult(t, rec, b, expect{status: http.StatusOK, remoteAddr: edgePeer, realIP: edgeIP})
			})
			t.Run(v.name+" rejected on "+host, func(t *testing.T) {
				b := &backend{}
				cfg := baseConfig()
				cfg.AllowMissingClientIP = false
				h := mustNew(t, b.handler(), cfg)
				header := map[string][]string{}
				if v.values != nil {
					header[cfConnectingIP] = v.values
				}
				rec := serve(h, request{host: host, remoteAddr: edgePeer, tls: aopChain(), header: header})
				assertResult(t, rec, b, expect{status: http.StatusForbidden})
			})
		}
	}

	t.Run("valid value with allowMissingClientIP false", func(t *testing.T) {
		b := &backend{}
		cfg := baseConfig()
		cfg.AllowMissingClientIP = false
		h := mustNew(t, b.handler(), cfg)
		rec := serve(h, request{
			host: openHost, remoteAddr: edgePeer, tls: aopChain(),
			header: map[string][]string{cfConnectingIP: {"203.0.113.7"}},
		})
		assertResult(t, rec, b, expect{
			status: http.StatusOK, remoteAddr: "203.0.113.7:44321", realIP: "203.0.113.7", cfIP: "203.0.113.7",
		})
	})

	t.Run("unverified with allowMissingClientIP false", func(t *testing.T) {
		b := &backend{}
		cfg := baseConfig()
		cfg.AllowMissingClientIP = false
		h := mustNew(t, b.handler(), cfg)
		rec := serve(h, request{host: openHost, remoteAddr: edgePeer})
		assertResult(t, rec, b, expect{status: http.StatusOK, remoteAddr: edgePeer, realIP: edgeIP})
	})
}

// U4
func TestOtherClientIPHeadersAreStripped(t *testing.T) {
	header := func() map[string][]string {
		return map[string][]string{
			"True-Client-Ip":     {"192.0.2.1"},
			"Cf-Connecting-Ipv6": {"2001:db8::1"},
			"Cf-Pseudo-Ipv4":     {"240.0.0.1"},
			"True_client_ip":     {"192.0.2.2"},
			"Cf_Connecting_Ipv6": {"2001:db8::2"},
			"cf_pseudo_ipv4":     {"240.0.0.2"},
			"Cf_connecting_ip":   {"192.0.2.3"},
			"X-Unrelated":        {"kept"},
		}
	}
	tests := []struct {
		name string
		tls  *tls.ConnectionState
		want expect
	}{
		{"unverified", nil, expect{status: http.StatusOK, remoteAddr: edgePeer, realIP: edgeIP}},
		{"verified", aopChain(), expect{
			status: http.StatusOK, remoteAddr: "203.0.113.7:44321", realIP: "203.0.113.7", cfIP: "203.0.113.7",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &backend{}
			h := mustNew(t, b.handler(), baseConfig())
			hdr := header()
			hdr[cfConnectingIP] = []string{"203.0.113.7"}
			rec := serve(h, request{host: openHost, remoteAddr: edgePeer, tls: tt.tls, header: hdr})
			assertResult(t, rec, b, tt.want)
			for key := range b.header {
				switch key {
				case xRealIP, cfConnectingIP, "X-Unrelated":
				default:
					t.Errorf("header %q reached the backend", key)
				}
			}
			if b.header.Get("X-Unrelated") != "kept" {
				t.Error("unrelated header was removed")
			}
		})
	}
}

// U5
func TestCertificatePinning(t *testing.T) {
	tests := []struct {
		name     string
		pin      *x509.Certificate
		tls      *tls.ConnectionState
		verified bool
	}{
		{"pinned leaf", aopLeaf, aopChain(), true},
		{"pinned intermediate", aopInter, aopChain(), true},
		{"pinned root", aopRoot, aopChain(), true},
		{"pin in second chain", aopRoot, verifiedState(
			[]*x509.Certificate{otherLeaf, otherRoot},
			[]*x509.Certificate{aopLeaf, aopRoot},
		), true},
		{"verified chain from another CA", aopRoot, verifiedState([]*x509.Certificate{otherLeaf, otherRoot}), false},
		{"other leaf under pinned leaf", aopLeaf, verifiedState([]*x509.Certificate{aopOtherLeaf, aopRoot}), false},
		{"peer certificates without verified chains", aopLeaf, &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{aopLeaf, aopRoot},
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &backend{}
			cfg := baseConfig()
			cfg.ClientCertFingerprints = []string{fingerprint(tt.pin)}
			h := mustNew(t, b.handler(), cfg)
			rec := serve(h, request{
				host: protectedHost, remoteAddr: edgePeer, tls: tt.tls,
				header: map[string][]string{cfConnectingIP: {"203.0.113.7"}},
			})
			if tt.verified {
				assertResult(t, rec, b, expect{
					status: http.StatusOK, remoteAddr: "203.0.113.7:44321", realIP: "203.0.113.7", cfIP: "203.0.113.7",
				})
			} else {
				assertResult(t, rec, b, expect{status: http.StatusForbidden})
			}
		})
	}
}

// U6
func TestProtectedHostAccess(t *testing.T) {
	tests := []struct {
		name string
		peer string
		tls  *tls.ConnectionState
		want expect
	}{
		{"pinned cert", edgePeer, aopChain(), expect{
			status: http.StatusOK, remoteAddr: "203.0.113.7:44321", realIP: "203.0.113.7", cfIP: "203.0.113.7",
		}},
		{"direct IPv4 CIDR", "192.0.2.10:5555", nil, expect{
			status: http.StatusOK, remoteAddr: "192.0.2.10:5555", realIP: "192.0.2.10",
		}},
		{"direct IPv6 CIDR", "[2001:db8:1::5]:5555", nil, expect{
			status: http.StatusOK, remoteAddr: "[2001:db8:1::5]:5555", realIP: "2001:db8:1::5",
		}},
		{"direct bare IP", "198.51.100.200:5555", nil, expect{
			status: http.StatusOK, remoteAddr: "198.51.100.200:5555", realIP: "198.51.100.200",
		}},
		{"direct IPv4-mapped peer", "[::ffff:192.0.2.10]:5555", nil, expect{
			status: http.StatusOK, remoteAddr: "[::ffff:192.0.2.10]:5555", realIP: "::ffff:192.0.2.10",
		}},
		{"outside peer", outsidePeer, nil, expect{status: http.StatusForbidden}},
		{"outside peer with TLS", outsidePeer, &tls.ConnectionState{}, expect{status: http.StatusForbidden}},
		{"bare IP does not cover neighbour", "198.51.100.201:5555", nil, expect{status: http.StatusForbidden}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &backend{}
			h := mustNew(t, b.handler(), baseConfig())
			// Cf-Connecting-Ip names an allowlisted address to prove it is
			// never used for the gate or, on unverified requests, the rewrite.
			rec := serve(h, request{
				host: protectedHost, remoteAddr: tt.peer, tls: tt.tls,
				header: map[string][]string{cfConnectingIP: {"203.0.113.7"}},
			})
			assertResult(t, rec, b, tt.want)
		})
	}

	t.Run("spoofed allowlisted client IP from outside peer", func(t *testing.T) {
		b := &backend{}
		h := mustNew(t, b.handler(), baseConfig())
		rec := serve(h, request{
			host: protectedHost, remoteAddr: outsidePeer,
			header: map[string][]string{cfConnectingIP: {"192.0.2.10"}},
		})
		assertResult(t, rec, b, expect{status: http.StatusForbidden})
	})

	t.Run("unprotected host from outside peer", func(t *testing.T) {
		b := &backend{}
		h := mustNew(t, b.handler(), baseConfig())
		rec := serve(h, request{host: openHost, remoteAddr: outsidePeer})
		assertResult(t, rec, b, expect{status: http.StatusOK, remoteAddr: outsidePeer, realIP: "203.0.113.50"})
	})
}

// U7
func TestHostCanonicalisation(t *testing.T) {
	tests := []struct {
		host      string
		sni       string
		protected bool
	}{
		{"protected.example.com", "", true},
		{"protected.example.com:443", "", true},
		{"protected.example.com:", "", true},
		{"PROTECTED.Example.COM", "", true},
		{"protected.example.com.", "", true},
		{"protected.example.com..:8443", "", true},
		{" protected.example.com ", "", true},
		{"protected.example.com", openHost, true},
		{openHost, protectedHost, false},
		{"[::1]:443", "", false},
		{"[::1]", "", false},
		{"", "", false},
		{"protected.example.com.test", "", false},
		{"sub.protected.example.com", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.host+" sni="+tt.sni, func(t *testing.T) {
			b := &backend{}
			h := mustNew(t, b.handler(), baseConfig())
			state := &tls.ConnectionState{ServerName: tt.sni}
			rec := serve(h, request{host: tt.host, remoteAddr: outsidePeer, tls: state})
			want := expect{status: http.StatusOK, remoteAddr: outsidePeer, realIP: "203.0.113.50"}
			if tt.protected {
				want = expect{status: http.StatusForbidden}
			}
			assertResult(t, rec, b, want)
		})
	}

	t.Run("protectAllHosts", func(t *testing.T) {
		for _, host := range []string{openHost, "", "[::1]:443"} {
			b := &backend{}
			cfg := baseConfig()
			cfg.ProtectedHosts = nil
			cfg.ProtectAllHosts = true
			h := mustNew(t, b.handler(), cfg)
			rec := serve(h, request{host: host, remoteAddr: outsidePeer})
			assertResult(t, rec, b, expect{status: http.StatusForbidden})
		}
	})
}

// U8
func TestChainedInstances(t *testing.T) {
	routerConfig := func(pin *x509.Certificate) *Config {
		cfg := CreateConfig()
		cfg.ClientCertFingerprints = []string{fingerprint(pin)}
		cfg.ProtectAllHosts = true
		cfg.DirectAccessCIDRs = []string{"192.0.2.0/24"}
		return cfg
	}
	entrypointConfig := func(pin *x509.Certificate) *Config {
		cfg := CreateConfig()
		cfg.ClientCertFingerprints = []string{fingerprint(pin)}
		return cfg
	}
	chain := func(t *testing.T, b *backend, entrypointPin, routerPin *x509.Certificate) http.Handler {
		t.Helper()
		router := mustNew(t, b.handler(), routerConfig(routerPin))
		return mustNew(t, router, entrypointConfig(entrypointPin))
	}
	cf := func(ip string) map[string][]string {
		return map[string][]string{cfConnectingIP: {ip}}
	}

	tests := []struct {
		name          string
		entrypointPin *x509.Certificate
		routerPin     *x509.Certificate
		req           request
		want          expect
	}{
		{
			"identical pins, verified", aopRoot, aopRoot,
			request{host: protectedHost, remoteAddr: edgePeer, tls: aopChain(), header: cf("203.0.113.7")},
			expect{status: http.StatusOK, remoteAddr: "203.0.113.7:44321", realIP: "203.0.113.7", cfIP: "203.0.113.7"},
		},
		{
			"identical pins, unverified spoof", aopRoot, aopRoot,
			request{host: protectedHost, remoteAddr: outsidePeer, header: cf("192.0.2.10")},
			expect{status: http.StatusForbidden},
		},
		{
			// The entrypoint rewrites RemoteAddr to an allowlisted IP; the
			// router must gate on the original peer, not the rewrite.
			"narrower router pin, claimed allowlisted IP", aopRoot, aopLeaf,
			request{
				host: protectedHost, remoteAddr: outsidePeer,
				tls: verifiedState([]*x509.Certificate{aopOtherLeaf, aopRoot}), header: cf("192.0.2.10"),
			},
			expect{status: http.StatusForbidden},
		},
		{
			"narrower router pin, allowlisted peer", aopRoot, aopLeaf,
			request{
				host: protectedHost, remoteAddr: "192.0.2.20:5555",
				tls: verifiedState([]*x509.Certificate{aopOtherLeaf, aopRoot}), header: cf("203.0.113.7"),
			},
			expect{status: http.StatusOK, remoteAddr: "192.0.2.20:5555", realIP: "192.0.2.20"},
		},
		{
			// A trusted proxy's X-Real-Ip, kept by Traefik, survives the
			// revert instead of being replaced by the peer IP.
			"narrower router pin, allowlisted peer with trusted X-Real-Ip", aopRoot, aopLeaf,
			request{
				host: protectedHost, remoteAddr: "192.0.2.20:5555",
				tls:    verifiedState([]*x509.Certificate{aopOtherLeaf, aopRoot}),
				header: map[string][]string{cfConnectingIP: {"203.0.113.7"}, xRealIP: {"203.0.113.9"}},
			},
			expect{status: http.StatusOK, remoteAddr: "192.0.2.20:5555", realIP: "203.0.113.9"},
		},
		{
			"entrypoint rejects, router accepts", otherRoot, aopLeaf,
			request{host: protectedHost, remoteAddr: edgePeer, tls: aopChain(), header: cf("203.0.113.7")},
			expect{status: http.StatusOK, remoteAddr: "203.0.113.7:44321", realIP: "203.0.113.7", cfIP: "203.0.113.7"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &backend{}
			rec := serve(chain(t, b, tt.entrypointPin, tt.routerPin), tt.req)
			assertResult(t, rec, b, tt.want)
		})
	}

	t.Run("router-level instance alone", func(t *testing.T) {
		b := &backend{}
		h := mustNew(t, b.handler(), routerConfig(aopLeaf))
		rec := serve(h, request{host: openHost, remoteAddr: edgePeer, tls: aopChain(), header: cf("203.0.113.7")})
		assertResult(t, rec, b, expect{
			status: http.StatusOK, remoteAddr: "203.0.113.7:44321", realIP: "203.0.113.7", cfIP: "203.0.113.7",
		})

		b = &backend{}
		h = mustNew(t, b.handler(), routerConfig(aopLeaf))
		rec = serve(h, request{host: openHost, remoteAddr: outsidePeer, header: cf("192.0.2.10")})
		assertResult(t, rec, b, expect{status: http.StatusForbidden})
	})
}

// U9
func TestNewValidation(t *testing.T) {
	valid := fingerprint(aopRoot)
	tests := []struct {
		name         string
		fingerprints []string
		hosts        []string
		cidrs        []string
		wantErr      string
	}{
		{"no fingerprints", nil, nil, nil, "at least one"},
		{"empty fingerprints", []string{}, nil, nil, "at least one"},
		{"blank fingerprint", []string{" "}, nil, nil, "clientCertFingerprints"},
		{"non-hex fingerprint", []string{strings.Repeat("zz", 32)}, nil, nil, "clientCertFingerprints"},
		{"short fingerprint", []string{valid[:62]}, nil, nil, "clientCertFingerprints"},
		{"long fingerprint", []string{valid + "00"}, nil, nil, "clientCertFingerprints"},
		{"invalid CIDR", []string{valid}, nil, []string{"192.0.2.0/33"}, "directAccessCIDRs"},
		{"invalid IP", []string{valid}, nil, []string{"not-an-ip"}, "directAccessCIDRs"},
		{"empty CIDR", []string{valid}, nil, []string{""}, "directAccessCIDRs"},
		{"mapped all IPv4", []string{valid}, nil, []string{"::ffff:0:0/96"}, "IPv4-mapped"},
		{"mapped range", []string{valid}, nil, []string{"::ffff:192.0.2.0/120"}, "IPv4-mapped"},
		{"empty host", []string{valid}, []string{""}, nil, "protectedHosts"},
		{"blank host", []string{valid}, []string{"  "}, nil, "protectedHosts"},
		{"dot host", []string{valid}, []string{"."}, nil, "protectedHosts"},
		{"wildcard host", []string{valid}, []string{"*.example.com"}, nil, "protectedHosts"},
		{"host with port", []string{valid}, []string{"example.com:443"}, nil, "protectedHosts"},
		{"host with path", []string{valid}, []string{"example.com/app"}, nil, "protectedHosts"},
		{"host with space", []string{valid}, []string{"example .com"}, nil, "protectedHosts"},
		{"host with tab", []string{valid}, []string{"example\t.com"}, nil, "protectedHosts"},
		{"non-ASCII host", []string{valid}, []string{"exämple.com"}, nil, "protectedHosts"},
		{"IPv6 host", []string{valid}, []string{"2001:db8::1"}, nil, "protectedHosts"},
		{"valid", []string{valid}, []string{"example.com"}, []string{"192.0.2.0/24"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := CreateConfig()
			cfg.ClientCertFingerprints = tt.fingerprints
			cfg.ProtectedHosts = tt.hosts
			cfg.DirectAccessCIDRs = tt.cidrs
			_, err := New(context.Background(), http.NotFoundHandler(), cfg, "test")
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
			}
		})
	}

	t.Run("normalisation", func(t *testing.T) {
		colons := strings.ToUpper(fingerprint(aopLeaf))
		var parts []string
		for i := 0; i < len(colons); i += 2 {
			parts = append(parts, colons[i:i+2])
		}
		cfg := CreateConfig()
		cfg.ClientCertFingerprints = []string{" " + strings.Join(parts, ":") + " "}
		cfg.ProtectedHosts = []string{" Protected.Example.COM. "}
		cfg.DirectAccessCIDRs = []string{" 192.0.2.0/24 ", " 2001:db8::1 ", "::ffff:198.51.100.7"}

		pinned := &backend{}
		h := mustNew(t, pinned.handler(), cfg)
		rec := serve(h, request{
			host: protectedHost, remoteAddr: edgePeer, tls: aopChain(),
			header: map[string][]string{cfConnectingIP: {"203.0.113.7"}},
		})
		assertResult(t, rec, pinned, expect{
			status: http.StatusOK, remoteAddr: "203.0.113.7:44321", realIP: "203.0.113.7", cfIP: "203.0.113.7",
		})

		for _, peer := range []string{"192.0.2.10:1", "[2001:db8::1]:1", "198.51.100.7:1"} {
			b := &backend{}
			h := mustNew(t, b.handler(), cfg)
			rec := serve(h, request{host: protectedHost, remoteAddr: peer})
			if rec.Code != http.StatusOK {
				t.Errorf("peer %s: status = %d, want 200", peer, rec.Code)
			}
		}

		b := &backend{}
		h = mustNew(t, b.handler(), cfg)
		rec = serve(h, request{host: protectedHost, remoteAddr: outsidePeer})
		assertResult(t, rec, b, expect{status: http.StatusForbidden})
	})
}

func TestRevokedCertFingerprints(t *testing.T) {
	rewritten := expect{
		status: http.StatusOK, remoteAddr: "203.0.113.7:44321", realIP: "203.0.113.7", cfIP: "203.0.113.7",
	}
	tests := []struct {
		name    string
		revoked *x509.Certificate
		tls     *tls.ConnectionState
		host    string
		peer    string
		want    expect
	}{
		{"revoked leaf on protected host", aopLeaf, aopChain(), protectedHost, edgePeer, expect{
			status: http.StatusForbidden,
		}},
		{"revoked leaf on open host", aopLeaf, aopChain(), openHost, edgePeer, expect{
			status: http.StatusOK, remoteAddr: edgePeer, realIP: edgeIP,
		}},
		{"revoked leaf from direct CIDR", aopLeaf, aopChain(), protectedHost, "192.0.2.10:5555", expect{
			status: http.StatusOK, remoteAddr: "192.0.2.10:5555", realIP: "192.0.2.10",
		}},
		{"revoked intermediate", aopInter, aopChain(), protectedHost, edgePeer, expect{
			status: http.StatusForbidden,
		}},
		// A pin in the first chain must not outweigh a revoked certificate in
		// an alternate chain.
		{"revoked intermediate in alternate chain", aopInter, verifiedState(
			[]*x509.Certificate{aopLeaf, aopRoot},
			[]*x509.Certificate{aopLeaf, aopInter, aopRoot},
		), protectedHost, edgePeer, expect{status: http.StatusForbidden}},
		{"sibling of revoked leaf", aopLeaf, verifiedState(
			[]*x509.Certificate{aopOtherLeaf, aopInter, aopRoot},
		), protectedHost, edgePeer, rewritten},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &backend{}
			cfg := baseConfig()
			cfg.RevokedCertFingerprints = []string{fingerprint(tt.revoked)}
			h := mustNew(t, b.handler(), cfg)
			rec := serve(h, request{
				host: tt.host, remoteAddr: tt.peer, tls: tt.tls,
				header: map[string][]string{cfConnectingIP: {"203.0.113.7"}},
			})
			assertResult(t, rec, b, tt.want)
		})
	}

	// The router instance runs last, so its revocation must undo the
	// entrypoint instance's rewrite.
	t.Run("router instance revokes after entrypoint rewrite", func(t *testing.T) {
		b := &backend{}
		routerCfg := baseConfig()
		routerCfg.RevokedCertFingerprints = []string{fingerprint(aopLeaf)}
		router := mustNew(t, b.handler(), routerCfg)
		h := mustNew(t, router, baseConfig())
		rec := serve(h, request{
			host: openHost, remoteAddr: edgePeer, tls: aopChain(),
			header: map[string][]string{cfConnectingIP: {"203.0.113.7"}},
		})
		assertResult(t, rec, b, expect{status: http.StatusOK, remoteAddr: edgePeer, realIP: edgeIP})
	})
}

func TestNewRevokedValidation(t *testing.T) {
	pin := fingerprint(aopRoot)
	colons := strings.ToUpper(pin)
	var parts []string
	for i := 0; i < len(colons); i += 2 {
		parts = append(parts, colons[i:i+2])
	}
	tests := []struct {
		name    string
		revoked []string
		wantErr string
	}{
		{"blank revoked fingerprint", []string{" "}, "revokedCertFingerprints"},
		{"non-hex revoked fingerprint", []string{strings.Repeat("zz", 32)}, "revokedCertFingerprints"},
		{"short revoked fingerprint", []string{pin[:62]}, "revokedCertFingerprints"},
		{"long revoked fingerprint", []string{pin + "00"}, "revokedCertFingerprints"},
		{"revoked fingerprint is pinned", []string{pin}, "in both"},
		{"revoked fingerprint is pinned in another form", []string{" " + strings.Join(parts, ":") + " "}, "in both"},
		{"valid", []string{fingerprint(aopLeaf), fingerprint(aopInter)}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := CreateConfig()
			cfg.ClientCertFingerprints = []string{pin}
			cfg.RevokedCertFingerprints = tt.revoked
			_, err := New(context.Background(), http.NotFoundHandler(), cfg, "test")
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}
