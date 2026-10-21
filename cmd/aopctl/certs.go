package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const (
	keyTypeECP256  = "ec-p256"
	keyTypeRSA3072 = "rsa-3072"
)

func validateKeyType(keyType string) error {
	if keyType != keyTypeECP256 && keyType != keyTypeRSA3072 {
		return usagef("invalid --key-type %q: want %s or %s", keyType, keyTypeECP256, keyTypeRSA3072)
	}
	return nil
}

func generateKey(keyType string) (crypto.Signer, error) {
	switch keyType {
	case keyTypeECP256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return key, nil
	case keyTypeRSA3072:
		key, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return nil, err
		}
		return key, nil
	}
	return nil, fmt.Errorf("unknown key type %q", keyType)
}

// newSerial returns a random, positive 128-bit serial number.
func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		serial, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, err
		}
		if serial.Sign() > 0 {
			return serial, nil
		}
	}
}

// createCA creates a self-signed, single-tier CA that may only sign leaves.
func createCA(cn, keyType string, days int, now time.Time) (*x509.Certificate, crypto.Signer, error) {
	key, err := generateKey(keyType)
	if err != nil {
		return nil, nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	notBefore := now.UTC().Add(-time.Hour)
	// CreateCertificate derives the SubjectKeyId from the public key for CA
	// templates, and leaves signed by this CA get a matching AuthorityKeyId.
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notBefore.AddDate(0, 0, days),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	cert, err := signCert(tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// createLeaf issues an AOP client certificate. It fails before generating
// anything when the CA would expire before the leaf.
func createLeaf(ca *x509.Certificate, caKey crypto.Signer, cn, keyType string, days int, now time.Time) (*x509.Certificate, crypto.Signer, error) {
	notBefore := now.UTC().Add(-time.Hour)
	notAfter := notBefore.AddDate(0, 0, days)
	if notAfter.After(ca.NotAfter) {
		return nil, nil, fmt.Errorf("the CA expires %s, before the new leaf would (%s): use a smaller --days or rotate the CA",
			ca.NotAfter.UTC().Format(time.RFC3339), notAfter.Format(time.RFC3339))
	}
	key, err := generateKey(keyType)
	if err != nil {
		return nil, nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	// Go's TLS server rejects client certificates without the clientAuth EKU.
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	cert, err := signCert(tmpl, ca, key.Public(), caKey)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func signCert(tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	return x509.ParseCertificate(der)
}

// verifyLeaf checks the leaf chains to the CA for client authentication.
func verifyLeaf(leaf, ca *x509.Certificate, now time.Time) error {
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err
}

func encodeCertPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// encodeKeyPEM encodes the key as PKCS#8, which Cloudflare accepts for both
// key types.
func encodeKeyPEM(key crypto.Signer) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("encode private key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// decodePEM returns the first PEM block of the wanted type. Errors never
// include the input, which may be a private key.
func decodePEM(data, blockType string) ([]byte, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(data)))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != blockType {
		return nil, fmt.Errorf("want a %s PEM block, got %s", blockType, block.Type)
	}
	return block.Bytes, nil
}

func parseCertPEM(data string) (*x509.Certificate, error) {
	der, err := decodePEM(data, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

func parseKeyPEM(data string) (crypto.Signer, error) {
	der, err := decodePEM(data, "PRIVATE KEY")
	if err != nil {
		return nil, fmt.Errorf("%w (want PKCS#8)", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported private key type %T", key)
	}
	return signer, nil
}

func keyMatchesCert(cert *x509.Certificate, key crypto.Signer) bool {
	pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	return ok && pub.Equal(cert.PublicKey)
}

// loadCA parses the CA pair and checks that it can sign leaves.
func loadCA(certPEM, keyPEM string) (*x509.Certificate, crypto.Signer, error) {
	cert, err := parseCACert(certPEM)
	if err != nil {
		return nil, nil, err
	}
	key, err := parseKeyPEM(keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("AOP_CA_KEY: %w", err)
	}
	if !keyMatchesCert(cert, key) {
		return nil, nil, errors.New("AOP_CA_KEY does not match the certificate in AOP_CA_CERT")
	}
	return cert, key, nil
}

func parseCACert(certPEM string) (*x509.Certificate, error) {
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("AOP_CA_CERT: %w", err)
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, errors.New("AOP_CA_CERT is not a CA certificate")
	}
	return cert, nil
}

// fingerprint formats the SHA-256 digest of the DER encoding as uppercase,
// colon-separated hex, as openssl x509 -fingerprint -sha256 does.
func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func describeKey(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return fmt.Sprintf("unknown (%T)", pub)
}

// caProfileWarnings lists the ways a certificate differs from the AOP CA
// profile: a CA with pathlen 0, certificate signing, and no EKU.
func caProfileWarnings(cert *x509.Certificate) []string {
	var warnings []string
	if !cert.BasicConstraintsValid || !cert.IsCA {
		warnings = append(warnings, "not a CA certificate")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		warnings = append(warnings, "key usage does not include certificate signing")
	}
	if len(cert.ExtKeyUsage) > 0 || len(cert.UnknownExtKeyUsage) > 0 {
		warnings = append(warnings, "has an extended key usage, so it may be used for more than AOP")
	}
	if cert.IsCA && (cert.MaxPathLen != 0 || !cert.MaxPathLenZero) {
		warnings = append(warnings, "path length is not 0, so it may sign intermediate CAs")
	}
	return warnings
}
