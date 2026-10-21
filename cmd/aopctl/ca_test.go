package main

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"
)

// vectorCA is a fixed CA certificate. vectorFingerprint is the output of
// openssl x509 -noout -fingerprint -sha256 for it.
const (
	vectorCA = `-----BEGIN CERTIFICATE-----
MIIBZzCCAQ2gAwIBAgICEJIwCgYIKoZIzj0EAwIwGTEXMBUGA1UEAxMORXhhbXBs
ZSBBT1AgQ0EwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAZMRcwFQYD
VQQDEw5FeGFtcGxlIEFPUCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNF9
uJ/vO3AjYkdwnGeN/e2eZHbQ04hskneAPlA3pFbTCQSfSRJAEHcphhBOXHURx45t
L5pMOGMUJyK73OoHVkWjRTBDMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMB0GA1UdDgQWBBQRqXOckKyZf4vQA4jLr2QKuCGlWzAKBggqhkjOPQQD
AgNIADBFAiEAo9ur3VGscrbX4wny93dFNOzr8AA4aP5WbTkwXV3LWe8CIDlU6455
ohfFPfilIEcPyzQMDZf1NYmtbBSFzvYheKLC
-----END CERTIFICATE-----
`
	vectorFingerprint = "6D:C4:0A:FB:5F:13:28:70:E4:47:04:AE:A7:3C:8E:66:F2:B4:63:A3:07:B2:D2:68:30:12:09:9B:77:AD:AB:DF"
)

type itemField struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Purpose string `json:"purpose"`
	Label   string `json:"label"`
	Value   string `json:"value"`
}

type item struct {
	Title    string      `json:"title"`
	Category string      `json:"category"`
	Fields   []itemField `json:"fields"`
}

func parseItem(t *testing.T, stdout string) (item, map[string]itemField) {
	t.Helper()
	var it item
	if err := json.Unmarshal([]byte(stdout), &it); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
	fields := map[string]itemField{}
	for _, f := range it.Fields {
		fields[f.ID] = f
	}
	return it, fields
}

// parseItemPair returns the CA pair from a ca create item template, checking
// that the key matches the certificate.
func parseItemPair(t *testing.T, stdout string) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	_, fields := parseItem(t, stdout)
	cert, key, err := loadCA(fields["ca_cert"].Value, fields["ca_key"].Value)
	if err != nil {
		t.Fatalf("item template pair: %v", err)
	}
	return cert, key
}

func TestCACreateRefusesTerminal(t *testing.T) {
	h := newHarness(t)
	h.stdoutTTY = true
	code, stdout, stderr := h.run("ca", "create")
	if code != 1 {
		t.Fatalf("exit %d, want 1; stderr:\n%s", code, stderr)
	}
	if stdout != "" {
		t.Errorf("wrote %d bytes to the terminal", len(stdout))
	}
	if !strings.Contains(stderr, "op item create") {
		t.Errorf("stderr does not explain how to pipe the output:\n%s", stderr)
	}
}

func TestCACreateOutput(t *testing.T) {
	h := newHarness(t)
	code, stdout, stderr := h.run("ca", "create", "--name", "Example AOP CA")
	if code != 0 {
		t.Fatalf("exit %d; stderr:\n%s", code, stderr)
	}
	it, fields := parseItem(t, stdout)
	if it.Category != "SECURE_NOTE" || it.Title != "Example AOP CA" {
		t.Errorf("category %q, title %q", it.Category, it.Title)
	}
	wantTypes := map[string]string{
		"ca_cert":            "STRING",
		"ca_key":             "CONCEALED",
		"fingerprint_sha256": "STRING",
		"notesPlain":         "STRING",
	}
	for id, typ := range wantTypes {
		if f, ok := fields[id]; !ok || f.Type != typ || f.Label != id {
			t.Errorf("field %s = %+v, want type %s", id, f, typ)
		}
	}
	if fields["notesPlain"].Purpose != "NOTES" || !strings.Contains(fields["notesPlain"].Value, "Expires") {
		t.Errorf("notesPlain = %+v", fields["notesPlain"])
	}

	cert, _ := parseItemPair(t, stdout)
	fp := fingerprint(cert)
	if fields["fingerprint_sha256"].Value != fp {
		t.Errorf("fingerprint field %q, want %q", fields["fingerprint_sha256"].Value, fp)
	}
	if !strings.Contains(stderr, fp) {
		t.Errorf("stderr does not show the fingerprint:\n%s", stderr)
	}
	if strings.Contains(stderr, "PRIVATE KEY") {
		t.Error("stderr contains the key")
	}

	code, stdout, stderr = h.run("ca", "create", "--name", "Example AOP CA", "--title", "Example item")
	if code != 0 {
		t.Fatalf("exit %d; stderr:\n%s", code, stderr)
	}
	if it, _ := parseItem(t, stdout); it.Title != "Example item" {
		t.Errorf("title %q, want the --title value", it.Title)
	}
}

func TestCAShow(t *testing.T) {
	t.Run("details", func(t *testing.T) {
		h := newHarness(t)
		h.stdin = "\n  " + vectorCA + "\n\n"
		code, stdout, stderr := h.run("ca", "show")
		if code != 0 {
			t.Fatalf("exit %d; stderr:\n%s", code, stderr)
		}
		for _, want := range []string{
			"Fingerprint: " + vectorFingerprint,
			"Subject:     CN=Example AOP CA",
			"Not before:  2026-01-01T00:00:00Z",
			"Not after:   2036-01-01T00:00:00Z",
			"Key type:    ECDSA P-256",
		} {
			if !strings.Contains(stdout, want) {
				t.Errorf("stdout lacks %q:\n%s", want, stdout)
			}
		}
		if strings.Contains(stdout, "Warning") {
			t.Errorf("unexpected warning:\n%s", stdout)
		}
	})

	t.Run("secret", func(t *testing.T) {
		h := newHarness(t)
		h.stdin = vectorCA
		code, stdout, stderr := h.run("ca", "show", "--secret", "cloudflare-aop-ca", "--namespace", "app")
		if code != 0 {
			t.Fatalf("exit %d; stderr:\n%s", code, stderr)
		}
		header := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: cloudflare-aop-ca\n  namespace: app\ntype: Opaque\nstringData:\n  ca.crt: |\n"
		body, ok := strings.CutPrefix(stdout, header)
		if !ok {
			t.Fatalf("manifest header mismatch:\n%s", stdout)
		}
		var pemLines []string
		for _, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
			pemLines = append(pemLines, strings.TrimPrefix(line, "    "))
		}
		cert, err := parseCertPEM(strings.Join(pemLines, "\n"))
		if err != nil {
			t.Fatalf("manifest certificate: %v", err)
		}
		if fingerprint(cert) != vectorFingerprint {
			t.Error("manifest holds a different certificate")
		}
	})

	t.Run("profile warning", func(t *testing.T) {
		h := newHarness(t)
		h.stdin = h.ca.issue(t)
		code, stdout, stderr := h.run("ca", "show")
		if code != 0 {
			t.Fatalf("exit %d; stderr:\n%s", code, stderr)
		}
		for _, want := range []string{"Warning:     not a CA certificate", "Warning:     has an extended key usage"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("stdout lacks %q:\n%s", want, stdout)
			}
		}
	})

	t.Run("terminal stdin", func(t *testing.T) {
		h := newHarness(t)
		h.stdinTTY = true
		code, _, stderr := h.run("ca", "show")
		if code != 1 || !strings.Contains(stderr, "stdin") {
			t.Errorf("exit %d, stderr:\n%s", code, stderr)
		}
	})

	t.Run("namespace without secret", func(t *testing.T) {
		h := newHarness(t)
		h.stdin = vectorCA
		if code, _, _ := h.run("ca", "show", "--namespace", "app"); code != 2 {
			t.Errorf("exit %d, want 2", code)
		}
	})
}
