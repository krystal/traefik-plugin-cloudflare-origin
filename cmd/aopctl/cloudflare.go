package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	defaultBaseURL = "https://api.cloudflare.com/client/v4"
	userAgent      = "aopctl"
	requestTimeout = 30 * time.Second

	hostnamesPath = "/zones/{zone}/origin_tls_client_auth/hostnames"
	certsPath     = hostnamesPath + "/certificates"

	// codeNoAssociation comes with a 404 for a hostname without an
	// association.
	codeNoAssociation = 1553

	maxResponseBytes = 10 << 20
	maxMessageBytes  = 200
	maxPages         = 100
)

// Certificate and association statuses.
const (
	statusActive             = "active"
	statusPendingDeletion    = "pending_deletion"
	statusDeleted            = "deleted"
	statusDeploymentTimedOut = "deployment_timed_out"
	statusDeletionTimedOut   = "deletion_timed_out"
)

type cfClient struct {
	baseURL string
	token   string
	zoneID  string
	http    *http.Client
}

type cfCert struct {
	ID          string `json:"id"`
	Certificate string `json:"certificate"`
	ExpiresOn   string `json:"expires_on"`
	Status      string `json:"status"`
}

// association is a hostname's AOP setting. Enabled is nil when the
// association was voided.
type association struct {
	Hostname string `json:"hostname"`
	CertID   string `json:"cert_id"`
	Enabled  *bool  `json:"enabled"`
	Status   string `json:"status"`
}

type apiMessage struct {
	Code    int
	Message string
}

// apiMessages decodes Cloudflare's errors and messages arrays, which hold
// objects or plain strings. Other entries are skipped.
type apiMessages []apiMessage

func (m *apiMessages) UnmarshalJSON(data []byte) error {
	var raw []json.RawMessage
	// A malformed list must not hide the response status, so it is ignored.
	if json.Unmarshal(data, &raw) != nil {
		return nil
	}
	for _, item := range raw {
		var obj struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		var s string
		switch {
		case json.Unmarshal(item, &obj) == nil:
			*m = append(*m, apiMessage{Code: obj.Code, Message: obj.Message})
		case json.Unmarshal(item, &s) == nil:
			*m = append(*m, apiMessage{Message: s})
		}
	}
	return nil
}

type envelope struct {
	// Success is nil when the field is missing, so the body is not an
	// envelope.
	Success    *bool           `json:"success"`
	Errors     apiMessages     `json:"errors"`
	Messages   apiMessages     `json:"messages"`
	Result     json.RawMessage `json:"result"`
	ResultInfo *struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

// apiError describes a failed request without request bodies, headers, raw
// response bodies or the zone ID.
type apiError struct {
	method string
	path   string
	// status is 0 when no response headers arrived.
	status   int
	codes    []int
	messages []string
	detail   string
	// transport is set when no complete response arrived: the request
	// failed before the headers, or reading the body failed.
	transport bool
	// decoded is set when the response was a Cloudflare envelope.
	decoded bool
	err     error
}

func (e *apiError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s", e.method, e.path)
	if e.status != 0 {
		fmt.Fprintf(&b, ": HTTP %d", e.status)
	}
	if len(e.codes) > 0 {
		codes := make([]string, len(e.codes))
		for i, c := range e.codes {
			codes[i] = strconv.Itoa(c)
		}
		fmt.Fprintf(&b, " (code %s)", strings.Join(codes, ", "))
	}
	if e.detail != "" {
		b.WriteString(": " + e.detail)
	}
	if len(e.messages) > 0 {
		b.WriteString(": " + strings.Join(e.messages, "; "))
	}
	return b.String()
}

func (e *apiError) Unwrap() error { return e.err }

func (e *apiError) hasCode(code int) bool {
	for _, c := range e.codes {
		if c == code {
			return true
		}
	}
	return false
}

// isNotFound reports a Cloudflare 404. A 404 that is not an envelope, such
// as an intermediary's error page, does not count.
func isNotFound(err error) bool {
	var apiErr *apiError
	return errors.As(err, &apiErr) && apiErr.decoded && apiErr.status == http.StatusNotFound
}

var (
	pemPattern    = regexp.MustCompile(`(?s)-----BEGIN.*?(?:-----END[^-]*-----|\z)`)
	base64Pattern = regexp.MustCompile(`[A-Za-z0-9+/=]{32,}`)
)

// sanitize makes text from a response safe to print. The token and zone ID
// are replaced first, so the later patterns cannot split them and leave a
// fragment behind.
func (c *cfClient) sanitize(s string) string {
	for _, secret := range []string{c.token, c.zoneID} {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, "[redacted]")
		}
	}
	s = pemPattern.ReplaceAllString(s, "[redacted PEM]")
	s = base64Pattern.ReplaceAllString(s, "[redacted]")
	if len(s) > maxMessageBytes {
		n := maxMessageBytes - len("...")
		for n > 0 && !utf8.RuneStart(s[n]) {
			n--
		}
		s = s[:n] + "..."
	}
	return s
}

// do sends one request and decodes the result into result, returning the
// page count for list requests. path uses {zone} for the zone ID.
func (c *cfClient) do(ctx context.Context, method, path string, query url.Values, body, result any) (int, error) {
	fail := func(e *apiError) (int, error) {
		e.method, e.path = method, path
		return 0, e
	}

	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fail(&apiError{detail: "encode request", err: err})
		}
		reqBody = bytes.NewReader(data)
	}
	u := c.baseURL + strings.Replace(path, "{zone}", url.PathEscape(c.zoneID), 1)
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reqBody)
	if err != nil {
		return fail(&apiError{detail: "invalid request URL"})
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	transportErr := func(status int, err error) (int, error) {
		// url.Error includes the full URL, and with it the zone ID.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return fail(&apiError{status: status, transport: true, detail: c.sanitize(err.Error()), err: err})
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return transportErr(0, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return transportErr(resp.StatusCode, err)
	}
	malformed := func(reason string) (int, error) {
		return fail(&apiError{
			status: resp.StatusCode,
			detail: c.sanitize(fmt.Sprintf("%s (content type %q)", reason, resp.Header.Get("Content-Type"))),
		})
	}
	if len(data) > maxResponseBytes {
		return malformed("response too large")
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil || env.Success == nil {
		return malformed("undecodable response")
	}
	success := *env.Success
	if resp.StatusCode < 200 || resp.StatusCode > 299 || !success {
		e := &apiError{status: resp.StatusCode, decoded: true}
		for _, m := range append(env.Errors, env.Messages...) {
			if m.Code != 0 {
				e.codes = append(e.codes, m.Code)
			}
			if m.Message != "" {
				e.messages = append(e.messages, c.sanitize(m.Message))
			}
		}
		if !success && resp.StatusCode >= 200 && resp.StatusCode <= 299 {
			e.detail = "request unsuccessful"
		}
		return fail(e)
	}
	if result != nil && len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, result); err != nil {
			return fail(&apiError{status: resp.StatusCode, detail: "undecodable result", decoded: true})
		}
	}
	if env.ResultInfo != nil {
		return env.ResultInfo.TotalPages, nil
	}
	return 0, nil
}

// listCerts returns every hostname certificate in the zone, across all pages.
func (c *cfClient) listCerts(ctx context.Context) ([]cfCert, error) {
	var all []cfCert
	for page := 1; ; page++ {
		var certs []cfCert
		totalPages, err := c.do(ctx, http.MethodGet, certsPath, url.Values{"page": {strconv.Itoa(page)}}, nil, &certs)
		if err != nil {
			return nil, err
		}
		all = append(all, certs...)
		if page >= totalPages || len(certs) == 0 {
			return all, nil
		}
		if page >= maxPages {
			return nil, fmt.Errorf("list certificates: more than %d pages", maxPages)
		}
	}
}

func (c *cfClient) getCert(ctx context.Context, id string) (*cfCert, error) {
	var cert cfCert
	if _, err := c.do(ctx, http.MethodGet, certsPath+"/"+url.PathEscape(id), nil, nil, &cert); err != nil {
		return nil, err
	}
	return &cert, nil
}

// uploadCert returns the new certificate's ID. It decodes nothing else, so
// drift in other fields cannot hide the ID.
func (c *cfClient) uploadCert(ctx context.Context, certPEM, keyPEM string) (string, error) {
	body := map[string]string{"certificate": certPEM, "private_key": keyPEM}
	var cert struct {
		ID string `json:"id"`
	}
	if _, err := c.do(ctx, http.MethodPost, certsPath, nil, body, &cert); err != nil {
		return "", err
	}
	return cert.ID, nil
}

func (c *cfClient) deleteCert(ctx context.Context, id string) error {
	_, err := c.do(ctx, http.MethodDelete, certsPath+"/"+url.PathEscape(id), nil, nil, nil)
	return err
}

// getAssociation returns nil when the hostname has no association.
func (c *cfClient) getAssociation(ctx context.Context, hostname string) (*association, error) {
	var assoc association
	_, err := c.do(ctx, http.MethodGet, hostnamesPath+"/"+url.PathEscape(hostname), nil, nil, &assoc)
	var apiErr *apiError
	if errors.As(err, &apiErr) && apiErr.status == http.StatusNotFound && apiErr.hasCode(codeNoAssociation) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if assoc.CertID == "" {
		return nil, nil
	}
	return &assoc, nil
}

type associationConfig struct {
	Hostname string `json:"hostname"`
	CertID   string `json:"cert_id"`
	Enabled  *bool  `json:"enabled"`
}

// associate enables certID for every hostname in one request.
func (c *cfClient) associate(ctx context.Context, certID string, hostnames []string) error {
	enabled := true
	config := make([]associationConfig, len(hostnames))
	for i, h := range hostnames {
		config[i] = associationConfig{Hostname: h, CertID: certID, Enabled: &enabled}
	}
	body := map[string][]associationConfig{"config": config}
	_, err := c.do(ctx, http.MethodPut, hostnamesPath, nil, body, nil)
	return err
}
