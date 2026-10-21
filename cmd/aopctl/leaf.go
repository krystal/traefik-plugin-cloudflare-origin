package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
)

const (
	defaultTimeout = 10 * time.Minute
	pollInterval   = 5 * time.Second

	// Cloudflare's limits: hostname certificates per zone, and hostnames
	// per certificate.
	maxZoneCerts = 10
	maxHostnames = 100

	pruneWarning = "aopctl can only check the hostnames you listed. If any other hostname still uses one of these certificates, deleting it breaks AOP for that hostname. Cloudflare's docs say such a delete is refused, but that is unverified."
)

// hostnames returns the --hostname flags, or AOP_HOSTNAMES when no flag is
// given, normalized and deduplicated.
func (a *app) hostnames(flags []string) ([]string, error) {
	entries := flags
	if len(entries) == 0 {
		entries = strings.FieldsFunc(a.getenv("AOP_HOSTNAMES"), func(r rune) bool {
			return r == ',' || unicode.IsSpace(r)
		})
	}
	seen := map[string]bool{}
	var hosts []string
	for _, raw := range entries {
		host := strings.TrimRight(strings.ToLower(strings.TrimSpace(raw)), ".")
		if host == "" {
			continue
		}
		if !validHostname(host) {
			return nil, usagef("invalid hostname %q: want an exact hostname", raw)
		}
		if !seen[host] {
			seen[host] = true
			hosts = append(hosts, host)
		}
	}
	if len(hosts) > maxHostnames {
		return nil, usagef("%d hostnames given: a certificate can serve at most %d", len(hosts), maxHostnames)
	}
	return hosts, nil
}

func validHostname(host string) bool {
	if strings.ContainsAny(host, "*:/,") {
		return false
	}
	for i := 0; i < len(host); i++ {
		if host[i] < 0x21 || host[i] > 0x7e {
			return false
		}
	}
	return true
}

var certIDPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// validateCertID keeps a --cert-id from changing the request path.
// Cloudflare's certificate IDs are UUIDs.
func validateCertID(id string) error {
	if !certIDPattern.MatchString(id) {
		return usagef("invalid --cert-id %q: want a Cloudflare certificate ID", id)
	}
	return nil
}

func requireHostnames(hosts []string) error {
	if len(hosts) == 0 {
		return errors.New("no hostnames: set AOP_HOSTNAMES or pass --hostname")
	}
	return nil
}

func hostnameFlags(hosts []string) string {
	var b strings.Builder
	for _, h := range hosts {
		b.WriteString(" --hostname " + h)
	}
	return b.String()
}

// readAssociations reads each hostname's association; a nil entry means none.
// Any error other than "no association" aborts.
func readAssociations(ctx context.Context, cf *cfClient, hosts []string) (map[string]*association, error) {
	assocs := make(map[string]*association, len(hosts))
	for _, h := range hosts {
		assoc, err := cf.getAssociation(ctx, h)
		if err != nil {
			return nil, fmt.Errorf("read association for %s: %w", h, err)
		}
		assocs[h] = assoc
	}
	return assocs, nil
}

// refuseDisabled stops a write that would re-enable AOP for a hostname
// someone disabled on purpose.
func refuseDisabled(hosts []string, assocs map[string]*association) error {
	for _, h := range hosts {
		if assoc := assocs[h]; assoc != nil && assoc.Enabled != nil && !*assoc.Enabled {
			return fmt.Errorf("%s has AOP disabled (enabled=false) for certificate %s: re-enable it in Cloudflare or remove it from the hostname list", h, assoc.CertID)
		}
	}
	return nil
}

// inUseCertID returns the certificate a hostname uses, or "" when its
// association is missing or voided.
func inUseCertID(assoc *association) string {
	if assoc == nil || assoc.Enabled == nil || !*assoc.Enabled {
		return ""
	}
	return assoc.CertID
}

// hostsUsing lists the hostnames whose association points at id. Disabled
// associations count; voided ones do not.
func hostsUsing(hosts []string, assocs map[string]*association, id string) []string {
	var using []string
	for _, h := range hosts {
		if assoc := assocs[h]; assoc != nil && assoc.Enabled != nil && assoc.CertID == id {
			using = append(using, h)
		}
	}
	return using
}

func formatEnabled(enabled *bool) string {
	if enabled == nil {
		return "null"
	}
	return fmt.Sprint(*enabled)
}

func describeAssociation(assoc *association) string {
	if assoc == nil {
		return "none"
	}
	return fmt.Sprintf("%s (enabled=%s, status=%s)", assoc.CertID, formatEnabled(assoc.Enabled), assoc.Status)
}

// certSignedBy parses a Cloudflare certificate and checks the CA signed it.
func certSignedBy(cert *cfCert, ca *x509.Certificate) (*x509.Certificate, error) {
	parsed, err := parseCertPEM(cert.Certificate)
	if err != nil {
		return nil, fmt.Errorf("certificate %s: %w", cert.ID, err)
	}
	if err := parsed.CheckSignatureFrom(ca); err != nil {
		return nil, fmt.Errorf("certificate %s is not signed by AOP_CA_CERT", cert.ID)
	}
	return parsed, nil
}

// otherCANote precedes a printed command for certificates AOP_CA_CERT did
// not sign, which leaf associate and leaf prune refuse.
func otherCANote(ids []string) string {
	return fmt.Sprintf("AOP_CA_CERT did not sign %s, so run the next command with AOP_CA_CERT set to the CA that did. During a CA rotation, that is the old CA.", strings.Join(ids, ", "))
}

// isTransient reports whether a polling read may succeed if retried: HTTP
// 429, a 5xx, or a transport error. Callers check the budget first.
func isTransient(err error) bool {
	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.transport || apiErr.status == http.StatusTooManyRequests || apiErr.status >= 500
}

// waitForCert polls an uploaded certificate until it is active.
func (a *app) waitForCert(ctx context.Context, cf *cfClient, id string) error {
	last := "last status unknown"
	timedOut := func() error {
		return fmt.Errorf("timed out waiting for certificate %s to become active: %s", id, last)
	}
	for {
		cert, err := cf.getCert(ctx, id)
		switch {
		case err == nil:
			last = "last status " + cert.Status
			switch cert.Status {
			case statusActive:
				return nil
			case statusDeploymentTimedOut, statusDeletionTimedOut, statusPendingDeletion, statusDeleted:
				return fmt.Errorf("certificate %s is %s", id, cert.Status)
			}
		case ctx.Err() != nil:
			return timedOut()
		case isTransient(err):
			last = "last error: " + err.Error()
		default:
			return fmt.Errorf("check certificate %s: %w", id, err)
		}
		if a.wait(ctx, pollInterval) != nil {
			return timedOut()
		}
	}
}

// waitForAssociations polls until every hostname points at id and is active,
// recording what it sees in observed.
func (a *app) waitForAssociations(ctx context.Context, cf *cfClient, id string, hosts []string, observed map[string]*association) error {
	pending := hosts
	// lastErr holds a hostname's transient read error, if its last read failed.
	lastErr := map[string]error{}
	for {
		var still []string
		for _, h := range pending {
			assoc, err := cf.getAssociation(ctx, h)
			if err != nil {
				if ctx.Err() != nil {
					return associationTimeout(id, pending, observed, lastErr)
				}
				if !isTransient(err) {
					return fmt.Errorf("check association for %s: %w", h, err)
				}
				lastErr[h] = err
				still = append(still, h)
				continue
			}
			delete(lastErr, h)
			observed[h] = assoc
			// A timed-out association still on another certificate has not
			// switched yet.
			if assoc != nil && assoc.CertID == id && strings.HasSuffix(assoc.Status, "_timed_out") {
				return fmt.Errorf("association for %s is %s", h, assoc.Status)
			}
			if assoc == nil || assoc.CertID != id || assoc.Status != statusActive {
				still = append(still, h)
			}
		}
		pending = still
		if len(pending) == 0 {
			return nil
		}
		if a.wait(ctx, pollInterval) != nil {
			return associationTimeout(id, pending, observed, lastErr)
		}
	}
}

func associationTimeout(id string, pending []string, observed map[string]*association, lastErr map[string]error) error {
	states := make([]string, len(pending))
	for i, h := range pending {
		state := "unknown"
		if err := lastErr[h]; err != nil {
			state = "error: " + err.Error()
		} else if assoc, ok := observed[h]; ok {
			state = describeAssociation(assoc)
		}
		states[i] = h + ": " + state
	}
	return fmt.Errorf("timed out waiting for hostnames to use certificate %s: last observed %s", id, strings.Join(states, "; "))
}

func (a *app) leafIssue(args []string) error {
	fs := a.flagSet("leaf issue", "[flags]")
	var hostFlags stringList
	fs.Var(&hostFlags, "hostname", "hostname to point at the new leaf (repeatable, replaces AOP_HOSTNAMES)")
	keyType := fs.String("key-type", keyTypeECP256, "key type: "+keyTypeECP256+" or "+keyTypeRSA3072)
	days := fs.Int("days", 365, "validity in days")
	name := fs.String("name", "aopctl AOP client", "leaf common name")
	dryRun := fs.Bool("dry-run", false, "show the plan without changing anything")
	timeout := fs.Duration("timeout", defaultTimeout, "time budget for the whole command")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := validateKeyType(*keyType); err != nil {
		return err
	}
	if err := validateDays(*days); err != nil {
		return err
	}
	if err := validateTimeout(*timeout); err != nil {
		return err
	}
	hosts, err := a.hostnames(hostFlags)
	if err != nil {
		return err
	}
	if err := requireHostnames(hosts); err != nil {
		return err
	}
	cf, err := a.cloudflare()
	if err != nil {
		return err
	}
	caCertPEM, err := a.requireEnv("AOP_CA_CERT")
	if err != nil {
		return err
	}
	caKeyPEM, err := a.requireEnv("AOP_CA_KEY")
	if err != nil {
		return err
	}
	caCert, caKey, err := loadCA(caCertPEM, caKeyPEM)
	if err != nil {
		return err
	}

	now := a.now()
	leaf, leafKey, err := createLeaf(caCert, caKey, *name, *keyType, *days, now)
	if err != nil {
		return err
	}
	if err := verifyLeaf(leaf, caCert, now); err != nil {
		return fmt.Errorf("the new leaf does not verify against AOP_CA_CERT: %w", err)
	}
	leafKeyPEM, err := encodeKeyPEM(leafKey)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	certs, err := cf.listCerts(ctx)
	if err != nil {
		return fmt.Errorf("list certificates: %w", err)
	}
	if len(certs) >= maxZoneCerts {
		return fmt.Errorf("the zone has %d hostname certificates, Cloudflare's limit is %d: delete unused ones first (see aopctl leaf status and aopctl leaf prune)", len(certs), maxZoneCerts)
	}
	signed := map[string]bool{}
	for i := range certs {
		if _, err := certSignedBy(&certs[i], caCert); err == nil {
			signed[certs[i].ID] = true
		}
	}
	original, err := readAssociations(ctx, cf, hosts)
	if err != nil {
		return err
	}
	if err := refuseDisabled(hosts, original); err != nil {
		return err
	}

	fmt.Fprintf(a.stderr, "New leaf:\n  subject:     %s\n  key type:    %s\n  expires:     %s\n  fingerprint: %s\nHostnames:\n",
		leaf.Subject, describeKey(leaf.PublicKey), leaf.NotAfter.UTC().Format(time.RFC3339), fingerprint(leaf))
	for _, h := range hosts {
		current := "none"
		if assoc := original[h]; assoc != nil {
			current = fmt.Sprintf("%s (enabled=%s)", assoc.CertID, formatEnabled(assoc.Enabled))
		}
		fmt.Fprintf(a.stderr, "  %s: %s -> new\n", h, current)
	}
	if *dryRun {
		fmt.Fprintln(a.stderr, "Dry run: nothing changed.")
		return nil
	}

	newID, err := cf.uploadCert(ctx, encodeCertPEM(leaf), leafKeyPEM)
	var apiErr *apiError
	// A 2xx response that could not be read may still have created a
	// certificate.
	if errors.As(err, &apiErr) && (!apiErr.decoded || apiErr.status >= 200 && apiErr.status <= 299) {
		return fmt.Errorf("upload outcome unknown: %w: a certificate may have been created, so run aopctl leaf status before retrying", err)
	}
	if err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}
	if newID == "" {
		return errors.New("upload outcome unknown: the response has no certificate ID, so run aopctl leaf status before retrying")
	}
	fmt.Fprintf(a.stderr, "Uploaded certificate %s, waiting for it to become active.\n", newID)

	r := &rollout{certID: newID, hosts: hosts, original: original, observed: map[string]*association{}, signed: signed}
	if err := a.rollOut(ctx, cf, r); err != nil {
		r.report(a.stderr)
		return err
	}

	fmt.Fprintf(a.stdout, "The listed hostnames now use certificate %s.\n", newID)
	var oldIDs, ownIDs, otherIDs []string
	seen := map[string]bool{}
	for _, h := range hosts {
		if id := inUseCertID(original[h]); id != "" && id != newID && !seen[id] {
			seen[id] = true
			oldIDs = append(oldIDs, id)
			if signed[id] {
				ownIDs = append(ownIDs, id)
			} else {
				otherIDs = append(otherIDs, id)
			}
		}
	}
	if len(oldIDs) == 0 {
		fmt.Fprintln(a.stdout, "The listed hostnames used no other certificate.")
		return nil
	}
	fmt.Fprintf(a.stdout, "They no longer use: %s\n", strings.Join(oldIDs, ", "))
	fmt.Fprintln(a.stdout, "Delete those soon. Cloudflare's docs leave open which certificate a hostname uses while several exist:")
	if len(ownIDs) > 0 {
		fmt.Fprintf(a.stdout, "  aopctl leaf prune --cert-id %s%s\n", strings.Join(ownIDs, " --cert-id "), hostnameFlags(hosts))
	}
	if len(otherIDs) > 0 {
		fmt.Fprintf(a.stdout, "  %s\n", otherCANote(otherIDs))
		fmt.Fprintf(a.stdout, "  aopctl leaf prune --cert-id %s%s\n", strings.Join(otherIDs, " --cert-id "), hostnameFlags(hosts))
	}
	return nil
}

// rollout tracks a new certificate's rollout so a failure can report how to
// resume or roll back.
type rollout struct {
	certID   string
	hosts    []string
	original map[string]*association
	// observed holds the last association read for each hostname. A
	// missing hostname is unknown.
	observed map[string]*association
	// signed records which listed certificates AOP_CA_CERT signed.
	signed map[string]bool
	// associateSent is set once the association PUT has been attempted.
	associateSent bool
}

func (a *app) rollOut(ctx context.Context, cf *cfClient, r *rollout) error {
	if err := a.waitForCert(ctx, cf, r.certID); err != nil {
		// No association was changed.
		for h, assoc := range r.original {
			r.observed[h] = assoc
		}
		return err
	}
	fmt.Fprintf(a.stderr, "Pointing %d hostnames at %s.\n", len(r.hosts), r.certID)
	r.associateSent = true
	if err := cf.associate(ctx, r.certID, r.hosts); err != nil {
		// The request may have been partly applied.
		for _, h := range r.hosts {
			if ctx.Err() != nil {
				break
			}
			if assoc, readErr := cf.getAssociation(ctx, h); readErr == nil {
				r.observed[h] = assoc
			}
		}
		return fmt.Errorf("associate hostnames: %w", err)
	}
	return a.waitForAssociations(ctx, cf, r.certID, r.hosts, r.observed)
}

func (r *rollout) report(w io.Writer) {
	fmt.Fprintf(w, "New certificate: %s\nHostnames (original -> observed):\n", r.certID)
	for _, h := range r.hosts {
		observed := "unknown"
		if assoc, ok := r.observed[h]; ok {
			observed = describeAssociation(assoc)
		}
		fmt.Fprintf(w, "  %s: %s -> %s\n", h, describeAssociation(r.original[h]), observed)
	}
	if !r.associateSent {
		// The certificate never became active, so leaf associate would
		// refuse it and there is nothing to roll back.
		fmt.Fprintf(w, "No hostname was changed. If certificate %s becomes active later, point the listed hostnames at it with:\n  aopctl leaf associate --cert-id %s%s\n", r.certID, r.certID, hostnameFlags(r.hosts))
		fmt.Fprintf(w, "Otherwise, delete it and run aopctl leaf issue again:\n  aopctl leaf prune --cert-id %s%s\n", r.certID, hostnameFlags(r.hosts))
		return
	}
	fmt.Fprintf(w, "To resume, run:\n  aopctl leaf associate --cert-id %s%s\n", r.certID, hostnameFlags(r.hosts))

	var oldIDs, unassociated []string
	byID := map[string][]string{}
	for _, h := range r.hosts {
		id := inUseCertID(r.original[h])
		if id == "" {
			unassociated = append(unassociated, h)
			continue
		}
		if byID[id] == nil {
			oldIDs = append(oldIDs, id)
		}
		byID[id] = append(byID[id], h)
	}
	fmt.Fprintln(w, "To roll back, run:")
	for _, id := range oldIDs {
		if !r.signed[id] {
			fmt.Fprintf(w, "  %s\n", otherCANote([]string{id}))
		}
		fmt.Fprintf(w, "  aopctl leaf associate --cert-id %s%s\n", id, hostnameFlags(byID[id]))
	}
	if len(unassociated) > 0 {
		config := make([]associationConfig, len(unassociated))
		for i, h := range unassociated {
			config[i] = associationConfig{Hostname: h, CertID: r.certID}
		}
		body, _ := json.Marshal(map[string][]associationConfig{"config": config})
		fmt.Fprintln(w, "  For hostnames that had no association, void the new one with this API request or in the Cloudflare dashboard. aopctl never voids associations.")
		fmt.Fprintf(w, "  PUT %s\n  %s\n", hostnamesPath, body)
	}
}

func (a *app) leafAssociate(args []string) error {
	fs := a.flagSet("leaf associate", "--cert-id ID [flags]")
	certID := fs.String("cert-id", "", "certificate to point the hostnames at (required)")
	var hostFlags stringList
	fs.Var(&hostFlags, "hostname", "hostname to point at the certificate (repeatable, replaces AOP_HOSTNAMES)")
	dryRun := fs.Bool("dry-run", false, "show the plan without changing anything")
	timeout := fs.Duration("timeout", defaultTimeout, "time budget for the whole command")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if strings.TrimSpace(*certID) == "" {
		return usagef("--cert-id is required")
	}
	if err := validateCertID(*certID); err != nil {
		return err
	}
	if err := validateTimeout(*timeout); err != nil {
		return err
	}
	hosts, err := a.hostnames(hostFlags)
	if err != nil {
		return err
	}
	if err := requireHostnames(hosts); err != nil {
		return err
	}
	cf, err := a.cloudflare()
	if err != nil {
		return err
	}
	caCertPEM, err := a.requireEnv("AOP_CA_CERT")
	if err != nil {
		return err
	}
	caCert, err := parseCACert(caCertPEM)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	cert, err := cf.getCert(ctx, *certID)
	if err != nil {
		return fmt.Errorf("read certificate %s: %w", *certID, err)
	}
	if _, err := certSignedBy(cert, caCert); err != nil {
		return err
	}
	if cert.Status != statusActive {
		return fmt.Errorf("certificate %s is %s, not %s", *certID, cert.Status, statusActive)
	}
	current, err := readAssociations(ctx, cf, hosts)
	if err != nil {
		return err
	}
	if err := refuseDisabled(hosts, current); err != nil {
		return err
	}
	for _, h := range hosts {
		fmt.Fprintf(a.stderr, "  %s: %s -> %s\n", h, describeAssociation(current[h]), *certID)
	}
	if *dryRun {
		fmt.Fprintln(a.stderr, "Dry run: nothing changed.")
		return nil
	}

	if err := cf.associate(ctx, *certID, hosts); err != nil {
		return fmt.Errorf("associate hostnames: %w", err)
	}
	if err := a.waitForAssociations(ctx, cf, *certID, hosts, map[string]*association{}); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "The listed hostnames now use certificate %s.\n", *certID)
	return nil
}

func (a *app) leafStatus(args []string) error {
	fs := a.flagSet("leaf status", "[flags]")
	var hostFlags stringList
	fs.Var(&hostFlags, "hostname", "hostname to report (repeatable, replaces AOP_HOSTNAMES)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	hosts, err := a.hostnames(hostFlags)
	if err != nil {
		return err
	}
	cf, err := a.cloudflare()
	if err != nil {
		return err
	}
	var caCert *x509.Certificate
	if v := strings.TrimSpace(a.getenv("AOP_CA_CERT")); v != "" {
		if caCert, err = parseCACert(v); err != nil {
			return err
		}
	}

	ctx := context.Background()
	certs, err := cf.listCerts(ctx)
	if err != nil {
		return fmt.Errorf("list certificates: %w", err)
	}
	assocs, err := readAssociations(ctx, cf, hosts)
	if err != nil {
		return err
	}

	now := a.now()
	fmt.Fprintf(a.stdout, "Certificates (%d of %d):\n", len(certs), maxZoneCerts)
	for i := range certs {
		c := &certs[i]
		fmt.Fprintf(a.stdout, "  %s\n    status:    %s\n", c.ID, c.Status)
		parsed, err := parseCertPEM(c.Certificate)
		if err != nil {
			fmt.Fprintf(a.stdout, "    certificate: unreadable (%v)\n", err)
		} else {
			fmt.Fprintf(a.stdout, "    subject:   %s\n    key type:  %s\n", parsed.Subject.CommonName, describeKey(parsed.PublicKey))
			// The fingerprint is what revokedCertFingerprints takes.
			fmt.Fprintf(a.stdout, "    fingerprint: %s\n", fingerprint(parsed))
		}
		fmt.Fprintf(a.stdout, "    expires:   %s\n", describeExpiry(c, parsed, now))
		signed := "unknown (AOP_CA_CERT not set)"
		if caCert != nil {
			signed = "no"
			if parsed != nil && parsed.CheckSignatureFrom(caCert) == nil {
				signed = "yes"
			}
		}
		fmt.Fprintf(a.stdout, "    signed by AOP_CA_CERT: %s\n", signed)
		using := "none of the listed hostnames"
		if hs := hostsUsing(hosts, assocs, c.ID); len(hs) > 0 {
			using = strings.Join(hs, ", ")
		}
		fmt.Fprintf(a.stdout, "    used by:   %s\n", using)
	}
	if len(hosts) > 0 {
		fmt.Fprintln(a.stdout, "Hostnames:")
		for _, h := range hosts {
			fmt.Fprintf(a.stdout, "  %s: %s\n", h, describeAssociation(assocs[h]))
		}
	}
	fmt.Fprintln(a.stdout, "Associations of hostnames you did not list cannot be discovered through the Cloudflare API.")
	return nil
}

// describeExpiry prefers the certificate's own expiry to Cloudflare's
// expires_on field.
func describeExpiry(c *cfCert, parsed *x509.Certificate, now time.Time) string {
	var notAfter time.Time
	if parsed != nil {
		notAfter = parsed.NotAfter
	} else if t, err := time.Parse(time.RFC3339, c.ExpiresOn); err == nil {
		notAfter = t
	} else {
		return c.ExpiresOn
	}
	expires := notAfter.UTC().Format(time.RFC3339)
	days := int(math.Floor(notAfter.Sub(now).Hours() / 24))
	if days < 0 {
		return expires + " (expired)"
	}
	return fmt.Sprintf("%s (%d days left)", expires, days)
}

type pruneTarget struct {
	cert   *cfCert
	parsed *x509.Certificate
	// pending is set for a certificate already being deleted, which gets
	// no second DELETE.
	pending bool
}

func (a *app) leafPrune(args []string) error {
	fs := a.flagSet("leaf prune", "--cert-id ID... [flags]")
	var idFlags, hostFlags stringList
	fs.Var(&idFlags, "cert-id", "certificate to delete (repeatable, required)")
	fs.Var(&hostFlags, "hostname", "hostname to check before deleting (repeatable, replaces AOP_HOSTNAMES)")
	yes := fs.Bool("yes", false, "delete without asking for confirmation")
	timeout := fs.Duration("timeout", defaultTimeout, "time budget for the whole command")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	var ids []string
	seen := map[string]bool{}
	for _, id := range idFlags {
		id = strings.TrimSpace(id)
		if err := validateCertID(id); err != nil {
			return err
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return usagef("--cert-id is required: run aopctl leaf status to find certificates the listed hostnames no longer use")
	}
	if err := validateTimeout(*timeout); err != nil {
		return err
	}
	hosts, err := a.hostnames(hostFlags)
	if err != nil {
		return err
	}
	if err := requireHostnames(hosts); err != nil {
		return err
	}
	cf, err := a.cloudflare()
	if err != nil {
		return err
	}
	caCertPEM, err := a.requireEnv("AOP_CA_CERT")
	if err != nil {
		return err
	}
	caCert, err := parseCACert(caCertPEM)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	failed := false
	refuse := func(id, reason string) {
		failed = true
		fmt.Fprintf(a.stderr, "Refused %s: %s\n", id, reason)
	}
	var targets []*pruneTarget
	for _, id := range ids {
		cert, err := cf.getCert(ctx, id)
		if isNotFound(err) {
			refuse(id, "not found")
			continue
		}
		if err != nil {
			return fmt.Errorf("read certificate %s: %w", id, err)
		}
		parsed, err := certSignedBy(cert, caCert)
		if err != nil {
			refuse(id, err.Error())
			continue
		}
		switch cert.Status {
		case statusDeleted:
			fmt.Fprintf(a.stderr, "Already deleted: %s\n", id)
			continue
		case statusPendingDeletion:
			targets = append(targets, &pruneTarget{cert: cert, parsed: parsed, pending: true})
			continue
		}
		targets = append(targets, &pruneTarget{cert: cert, parsed: parsed})
	}

	assocs, err := readAssociations(ctx, cf, hosts)
	if err != nil {
		return err
	}
	var kept []*pruneTarget
	deletes := 0
	for _, t := range targets {
		if !t.pending {
			if using := hostsUsing(hosts, assocs, t.cert.ID); len(using) > 0 {
				refuse(t.cert.ID, "still used by "+strings.Join(using, ", "))
				continue
			}
			deletes++
		}
		kept = append(kept, t)
	}
	targets = kept

	if len(targets) > 0 {
		fmt.Fprintln(a.stderr, "Certificates to delete:")
		for _, t := range targets {
			state := t.cert.Status
			if t.pending {
				state += ", waiting for the earlier delete to finish"
			}
			fmt.Fprintf(a.stderr, "  %s  %s, expires %s, status %s\n",
				t.cert.ID, t.parsed.Subject.CommonName, t.parsed.NotAfter.UTC().Format(time.RFC3339), state)
		}
		fmt.Fprintln(a.stderr, pruneWarning)
	}
	if deletes > 0 && !*yes {
		ok, err := a.confirm(fmt.Sprintf("Delete %d certificate(s)? [y/N] ", deletes))
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("aborted: nothing deleted")
		}
	}

	for _, t := range targets {
		id := t.cert.ID
		if !t.pending {
			// Catch a hostname pointed at this certificate after the preview.
			current, err := readAssociations(ctx, cf, hosts)
			if err != nil {
				failed = true
				fmt.Fprintf(a.stderr, "Failed %s: %v\n", id, err)
				continue
			}
			if using := hostsUsing(hosts, current, id); len(using) > 0 {
				refuse(id, "now used by "+strings.Join(using, ", "))
				continue
			}
			if err := cf.deleteCert(ctx, id); err != nil {
				failed = true
				fmt.Fprintf(a.stderr, "Failed %s: %v\n", id, err)
				continue
			}
		}
		if err := a.waitForDeletion(ctx, cf, id); err != nil {
			failed = true
			fmt.Fprintf(a.stderr, "Failed %s: %v\n", id, err)
			continue
		}
		fmt.Fprintf(a.stderr, "Deleted %s\n", id)
	}
	if failed {
		return errors.New("some certificates were not deleted")
	}
	return nil
}

// waitForDeletion polls until the certificate is gone or deleted.
func (a *app) waitForDeletion(ctx context.Context, cf *cfClient, id string) error {
	last := "last status unknown"
	timedOut := func() error {
		return fmt.Errorf("timed out waiting for the delete to finish: %s", last)
	}
	for {
		cert, err := cf.getCert(ctx, id)
		switch {
		case isNotFound(err):
			return nil
		case err == nil:
			last = "last status " + cert.Status
			switch cert.Status {
			case statusDeleted:
				return nil
			case statusDeletionTimedOut:
				return fmt.Errorf("the delete failed at Cloudflare: status %s", cert.Status)
			}
		case ctx.Err() != nil:
			return timedOut()
		case isTransient(err):
			last = "last error: " + err.Error()
		default:
			return fmt.Errorf("check certificate: %w", err)
		}
		if a.wait(ctx, pollInterval) != nil {
			return timedOut()
		}
	}
}

// confirm asks on the controlling terminal. Only "y" or "yes" confirms.
func (a *app) confirm(prompt string) (bool, error) {
	tty, err := a.openTTY()
	if err != nil {
		return false, fmt.Errorf("cannot open the terminal to confirm, pass --yes to skip confirmation: %w", err)
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	line, err := bufio.NewReader(tty).ReadString('\n')
	// EOF before a newline aborts, whatever was typed.
	if errors.Is(err, io.EOF) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}
