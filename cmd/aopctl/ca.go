package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

const maxCertInput = 1 << 20

var (
	// Kubernetes object names: a Secret name is a DNS subdomain and a
	// namespace is a DNS label.
	secretNamePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
	namespacePattern  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
)

// opItem is a 1Password item template, as read by "op item create -".
type opItem struct {
	Title    string    `json:"title"`
	Category string    `json:"category"`
	Fields   []opField `json:"fields"`
}

type opField struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Purpose string `json:"purpose,omitempty"`
	Label   string `json:"label"`
	Value   string `json:"value"`
}

func (a *app) caCreate(args []string) error {
	fs := a.flagSet("ca create", "[flags] | op item create --vault <vault> -")
	name := fs.String("name", "aopctl AOP CA", "CA common name")
	keyType := fs.String("key-type", keyTypeECP256, "key type: "+keyTypeECP256+" or "+keyTypeRSA3072)
	days := fs.Int("days", 3650, "validity in days")
	title := fs.String("title", "", "1Password item title (default: the common name)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := validateKeyType(*keyType); err != nil {
		return err
	}
	if err := validateDays(*days); err != nil {
		return err
	}
	if a.stdoutIsTerminal() {
		return errors.New("refusing to write the CA key to a terminal: pipe the output to \"op item create --vault <vault> -\"")
	}
	if *title == "" {
		*title = *name
	}

	cert, key, err := createCA(*name, *keyType, *days, a.now())
	if err != nil {
		return err
	}
	keyPEM, err := encodeKeyPEM(key)
	if err != nil {
		return err
	}
	fp := fingerprint(cert)
	expires := cert.NotAfter.UTC().Format(time.RFC3339)
	item := opItem{
		Title:    *title,
		Category: "SECURE_NOTE",
		Fields: []opField{
			{
				ID: "notesPlain", Type: "STRING", Purpose: "NOTES", Label: "notesPlain",
				Value: fmt.Sprintf("Cloudflare Authenticated Origin Pulls client CA, created by aopctl. Expires %s.", expires),
			},
			{ID: "ca_cert", Type: "STRING", Label: "ca_cert", Value: encodeCertPEM(cert)},
			{ID: "ca_key", Type: "CONCEALED", Label: "ca_key", Value: keyPEM},
			{ID: "fingerprint_sha256", Type: "STRING", Label: "fingerprint_sha256", Value: fp},
		},
	}
	enc := json.NewEncoder(a.stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(item); err != nil {
		return fmt.Errorf("write item template: %w", err)
	}

	fmt.Fprintf(a.stderr, `Created CA %q (%s), expires %s.
SHA-256 fingerprint: %s

Next steps:
  1. Reference the item's ca_cert and ca_key fields as AOP_CA_CERT and
     AOP_CA_KEY in the env file you pass to op run.
  2. Pin the fingerprint in the plugin's clientCertFingerprints.
  3. Create the Traefik Secret from the certificate with
     op read "op://<vault>/<item>/ca_cert" | aopctl ca show --secret <name>
`, *name, describeKey(cert.PublicKey), expires, fp)
	return nil
}

func (a *app) caShow(args []string) error {
	fs := a.flagSet("ca show", "[flags] < ca.crt")
	secret := fs.String("secret", "", "print only a Kubernetes Secret with this name holding the certificate")
	namespace := fs.String("namespace", "", "namespace for the Secret (requires --secret)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *namespace != "" && *secret == "" {
		return usagef("--namespace requires --secret")
	}
	if *secret != "" && (len(*secret) > 253 || !secretNamePattern.MatchString(*secret)) {
		return usagef("invalid --secret %q: want a Kubernetes object name", *secret)
	}
	if *namespace != "" && (len(*namespace) > 63 || !namespacePattern.MatchString(*namespace)) {
		return usagef("invalid --namespace %q: want a Kubernetes namespace name", *namespace)
	}
	if a.stdinIsTerminal() {
		return errors.New("ca show reads the CA certificate PEM from stdin: pipe it in, for example with op read")
	}

	data, err := io.ReadAll(io.LimitReader(a.stdin, maxCertInput))
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	cert, err := parseCertPEM(string(data))
	if err != nil {
		return fmt.Errorf("stdin: %w", err)
	}
	warnings := caProfileWarnings(cert)

	if *secret != "" {
		for _, w := range warnings {
			fmt.Fprintf(a.stderr, "warning: %s\n", w)
		}
		writeSecretManifest(a.stdout, *secret, *namespace, encodeCertPEM(cert))
		return nil
	}

	fmt.Fprintf(a.stdout, "Subject:     %s\n", cert.Subject)
	fmt.Fprintf(a.stdout, "Fingerprint: %s\n", fingerprint(cert))
	fmt.Fprintf(a.stdout, "Not before:  %s\n", cert.NotBefore.UTC().Format(time.RFC3339))
	fmt.Fprintf(a.stdout, "Not after:   %s\n", cert.NotAfter.UTC().Format(time.RFC3339))
	fmt.Fprintf(a.stdout, "Key type:    %s\n", describeKey(cert.PublicKey))
	for _, w := range warnings {
		fmt.Fprintf(a.stdout, "Warning:     %s\n", w)
	}
	return nil
}

// writeSecretManifest writes the Secret from the README's first example.
func writeSecretManifest(w io.Writer, name, namespace, certPEM string) {
	fmt.Fprintf(w, "apiVersion: v1\nkind: Secret\nmetadata:\n  name: %s\n", name)
	if namespace != "" {
		fmt.Fprintf(w, "  namespace: %s\n", namespace)
	}
	fmt.Fprint(w, "type: Opaque\nstringData:\n  ca.crt: |\n")
	for _, line := range strings.Split(strings.TrimSpace(certPEM), "\n") {
		fmt.Fprintf(w, "    %s\n", line)
	}
}
