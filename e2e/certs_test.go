//go:build e2e

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newAuthority(t *testing.T, name string) *authority {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          newSerial(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA %s: %v", name, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA %s: %v", name, err)
	}
	return &authority{cert: cert, key: key}
}

// issue signs a leaf for client auth, or for server auth when dnsNames is set.
func (a *authority) issue(t *testing.T, name string, dnsNames ...string) tls.Certificate {
	t.Helper()
	key := newKey(t)
	usage := x509.ExtKeyUsageClientAuth
	if len(dnsNames) > 0 {
		usage = x509.ExtKeyUsageServerAuth
	}
	tmpl := &x509.Certificate{
		SerialNumber: newSerial(t),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatalf("issue %s: %v", name, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func newSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	return serial
}

func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// fixtures holds every certificate the suite uses. Only the server pair and
// the client-auth CAs are written to disk for Traefik.
type fixtures struct {
	serverPool *x509.CertPool

	aopCA   *authority
	otherCA *authority

	// cfLeaf and cfOtherLeaf both chain to aopCA; cfOtherLeaf stands in for
	// a different AOP leaf that a router-level leaf pin must reject.
	cfLeaf      tls.Certificate
	cfOtherLeaf tls.Certificate
	otherLeaf   tls.Certificate
	rogueLeaf   tls.Certificate

	serverCert, serverKey, aopCAFile, otherCAFile string
}

func newFixtures(t *testing.T, dir string, hosts []string) *fixtures {
	t.Helper()
	serverCA := newAuthority(t, "e2e server CA")
	f := &fixtures{
		serverPool: x509.NewCertPool(),
		aopCA:      newAuthority(t, "e2e AOP CA"),
		otherCA:    newAuthority(t, "e2e other client CA"),
	}
	f.serverPool.AddCert(serverCA.cert)
	f.cfLeaf = f.aopCA.issue(t, "e2e cloudflare origin pull")
	f.cfOtherLeaf = f.aopCA.issue(t, "e2e cloudflare other origin pull")
	f.otherLeaf = f.otherCA.issue(t, "e2e other client")
	f.rogueLeaf = newAuthority(t, "e2e rogue CA").issue(t, "e2e rogue client")

	server := serverCA.issue(t, "e2e server", hosts...)
	keyDER, err := x509.MarshalECPrivateKey(server.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}

	f.serverCert = filepath.Join(dir, "server.crt")
	f.serverKey = filepath.Join(dir, "server.key")
	f.aopCAFile = filepath.Join(dir, "aop-ca.crt")
	f.otherCAFile = filepath.Join(dir, "other-ca.crt")
	writePEM(t, f.serverCert, "CERTIFICATE", server.Certificate[0])
	writePEM(t, f.serverKey, "EC PRIVATE KEY", keyDER)
	writePEM(t, f.aopCAFile, "CERTIFICATE", f.aopCA.cert.Raw)
	writePEM(t, f.otherCAFile, "CERTIFICATE", f.otherCA.cert.Raw)
	return f
}
