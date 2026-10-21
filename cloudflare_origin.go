// Package traefik_plugin_cloudflare_origin is a Traefik middleware that
// restores the client IP from Cloudflare's Cf-Connecting-Ip header for
// requests that present a pinned Authenticated Origin Pulls certificate, and
// that can restrict hosts to such requests or to allowlisted source CIDRs.
package traefik_plugin_cloudflare_origin

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
)

const (
	cfConnectingIP = "Cf-Connecting-Ip"
	xRealIP        = "X-Real-Ip"
)

// strippedHeaders are client-IP headers that apps must never trust. They are
// matched after mapping "_" to "-" and canonicalising, as Traefik does for
// X-Forwarded-*, because Go's server keeps underscore variants as separate
// keys and some backends treat them as equivalent.
var strippedHeaders = map[string]bool{
	"True-Client-Ip":     true,
	"Cf-Connecting-Ipv6": true,
	"Cf-Pseudo-Ipv4":     true,
	cfConnectingIP:       true,
}

// Config is the plugin configuration. Traefik matches keys to field names
// case-insensitively.
type Config struct {
	ClientCertFingerprints  []string `json:"clientCertFingerprints"`
	RevokedCertFingerprints []string `json:"revokedCertFingerprints"`
	ProtectedHosts          []string `json:"protectedHosts"`
	DirectAccessCIDRs       []string `json:"directAccessCIDRs"`
	ProtectAllHosts         bool     `json:"protectAllHosts"`
	AllowMissingClientIP    bool     `json:"allowMissingClientIP"`
}

// CreateConfig returns the default configuration.
func CreateConfig() *Config {
	return &Config{AllowMissingClientIP: true}
}

// CloudflareOrigin is the middleware handler.
type CloudflareOrigin struct {
	next                 http.Handler
	fingerprints         map[string]bool
	revoked              map[string]bool
	protectedHosts       map[string]bool
	directAccess         []*net.IPNet
	protectAllHosts      bool
	allowMissingClientIP bool
}

// New validates the configuration and creates the middleware.
func New(_ context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	c := &CloudflareOrigin{
		next:                 next,
		fingerprints:         map[string]bool{},
		revoked:              map[string]bool{},
		protectedHosts:       map[string]bool{},
		protectAllHosts:      cfg.ProtectAllHosts,
		allowMissingClientIP: cfg.AllowMissingClientIP,
	}

	for _, raw := range cfg.ClientCertFingerprints {
		fp, err := parseFingerprint("clientCertFingerprints", raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		c.fingerprints[fp] = true
	}
	if len(c.fingerprints) == 0 {
		return nil, fmt.Errorf("%s: clientCertFingerprints must contain at least one fingerprint", name)
	}

	for _, raw := range cfg.RevokedCertFingerprints {
		fp, err := parseFingerprint("revokedCertFingerprints", raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if c.fingerprints[fp] {
			return nil, fmt.Errorf("%s: fingerprint %q is in both clientCertFingerprints and revokedCertFingerprints", name, raw)
		}
		c.revoked[fp] = true
	}

	for _, raw := range cfg.ProtectedHosts {
		host, err := parseHost(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		c.protectedHosts[host] = true
	}

	for _, raw := range cfg.DirectAccessCIDRs {
		ipNet, err := parseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		c.directAccess = append(c.directAccess, ipNet)
	}

	return c, nil
}

func parseFingerprint(option, raw string) (string, error) {
	fp := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw), ":", ""))
	b, err := hex.DecodeString(fp)
	if err != nil || len(b) != sha256.Size {
		return "", fmt.Errorf("invalid %s entry %q: want a SHA-256 hex digest", option, raw)
	}
	return fp, nil
}

func parseHost(raw string) (string, error) {
	host := strings.TrimRight(strings.ToLower(strings.TrimSpace(raw)), ".")
	if host == "" || strings.ContainsAny(host, "*:/") {
		return "", fmt.Errorf("invalid protectedHosts entry %q: want an exact hostname", raw)
	}
	for i := 0; i < len(host); i++ {
		if host[i] < 0x21 || host[i] > 0x7e {
			return "", fmt.Errorf("invalid protectedHosts entry %q: want an exact hostname", raw)
		}
	}
	return host, nil
}

func parseCIDR(raw string) (*net.IPNet, error) {
	s := strings.TrimSpace(raw)
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("invalid directAccessCIDRs entry %q", raw)
		}
		if ip4 := ip.To4(); ip4 != nil {
			return &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}, nil
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
	}

	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, fmt.Errorf("invalid directAccessCIDRs entry %q: %w", raw, err)
	}
	// net.IPNet applies only the last 32 bits of the mask to an IPv4-mapped
	// network, so "::ffff:0:0/96" would allow every IPv4 address.
	if strings.Contains(s, ":") && ipNet.IP.To4() != nil {
		return nil, fmt.Errorf("invalid directAccessCIDRs entry %q: use the IPv4 form of IPv4-mapped ranges", raw)
	}
	return ipNet, nil
}

// contextKey is unexported so no other code can set or read the original
// request inputs.
type contextKey struct{}

// originalInputs is captured by the first instance in a chain, before any
// instance rewrites the request.
type originalInputs struct {
	remoteAddr string
	peerIP     string
	port       string
	clientIPs  []string
	realIPs    []string
}

func captureOriginal(req *http.Request) *originalInputs {
	orig := &originalInputs{remoteAddr: req.RemoteAddr}
	if host, port, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		if i := strings.IndexByte(host, '%'); i >= 0 {
			host = host[:i]
		}
		orig.peerIP = host
		orig.port = port
	}
	orig.clientIPs = append(orig.clientIPs, req.Header[cfConnectingIP]...)
	orig.realIPs = append(orig.realIPs, req.Header[xRealIP]...)
	return orig
}

func (c *CloudflareOrigin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Every instance decides from the original peer and header, so a later
	// instance with a narrower pin can undo an earlier rewrite instead of
	// trusting it.
	orig, ok := req.Context().Value(contextKey{}).(*originalInputs)
	if !ok {
		orig = captureOriginal(req)
		req = req.WithContext(context.WithValue(req.Context(), contextKey{}, orig))
	}

	verified := c.verified(req.TLS)

	for key := range req.Header {
		if strippedHeaders[http.CanonicalHeaderKey(strings.ReplaceAll(key, "_", "-"))] {
			delete(req.Header, key)
		}
	}

	var clientIP net.IP
	if verified && len(orig.clientIPs) == 1 && orig.port != "" {
		clientIP = net.ParseIP(orig.clientIPs[0])
	}

	if clientIP != nil {
		req.RemoteAddr = net.JoinHostPort(clientIP.String(), orig.port)
		req.Header.Set(xRealIP, clientIP.String())
		req.Header.Set(cfConnectingIP, clientIP.String())
	} else {
		// Restore what Traefik passed in. It keeps a trusted peer's X-Real-Ip
		// and otherwise sets the peer IP, so overwriting it here would drop a
		// trusted proxy's value.
		req.RemoteAddr = orig.remoteAddr
		if len(orig.realIPs) > 0 {
			req.Header[xRealIP] = append([]string(nil), orig.realIPs...)
		} else {
			req.Header.Del(xRealIP)
		}

		// Without this, an edge IP would reach the backend as the client.
		if verified && !c.allowMissingClientIP {
			forbidden(rw)
			return
		}
	}

	if !verified && c.isProtected(req.Host) && !c.isDirectAccess(orig.peerIP) {
		forbidden(rw)
		return
	}

	c.next.ServeHTTP(rw, req)
}

// verified reports whether a verified chain contains a certificate pinned by
// this instance and no verified chain contains a revoked one. PeerCertificates
// alone are not trusted: they are present without verification under
// RequireAnyClientCert, and a chain verified by a different TLS option's CA
// must not count either. A revoked certificate in any chain wins over a pin in
// another, so an alternate path around a revoked intermediate cannot verify.
func (c *CloudflareOrigin) verified(state *tls.ConnectionState) bool {
	if state == nil {
		return false
	}
	pinned := false
	for _, chain := range state.VerifiedChains {
		for _, cert := range chain {
			sum := sha256.Sum256(cert.Raw)
			fp := hex.EncodeToString(sum[:])
			if c.revoked[fp] {
				return false
			}
			if c.fingerprints[fp] {
				pinned = true
			}
		}
	}
	return pinned
}

// isProtected matches Traefik's routing host, with trailing dots trimmed so
// "host." cannot reach a protected router unprotected.
func (c *CloudflareOrigin) isProtected(reqHost string) bool {
	if c.protectAllHosts {
		return true
	}
	host := reqHost
	if strings.Contains(host, ":") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
	}
	host = strings.TrimRight(strings.ToLower(strings.TrimSpace(host)), ".")
	return c.protectedHosts[host]
}

func (c *CloudflareOrigin) isDirectAccess(peerIP string) bool {
	ip := net.ParseIP(peerIP)
	if ip == nil {
		return false
	}
	for _, ipNet := range c.directAccess {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

func forbidden(rw http.ResponseWriter) {
	http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
}
