// Command aopctl manages a dedicated client CA for Cloudflare Authenticated
// Origin Pulls (AOP) and the per-hostname leaf certificates it issues.
//
// Secrets come from environment variables, for example through
// "op run --env-file", and keys are never written to disk.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const usageText = `Usage: aopctl <command> [flags]

Commands:
  ca create       Create a CA and print a 1Password item template
  ca show         Describe the CA certificate read from stdin
  leaf issue      Issue a leaf, upload it and point the hostnames at it
  leaf associate  Point the hostnames at an existing leaf
  leaf status     List leaf certificates and hostname associations
  leaf prune      Delete the named leaf certificates

Environment:
  AOP_CA_CERT           CA certificate PEM
  AOP_CA_KEY            CA private key PEM (PKCS#8), for leaf issue
  CLOUDFLARE_API_TOKEN  Zone > SSL and Certificates > Edit
  CLOUDFLARE_ZONE_ID    the zone's ID
  AOP_HOSTNAMES         hostnames this CA serves, comma- or space-separated

Run "aopctl <command> -h" for a command's flags.
`

type app struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	getenv func(string) string

	stdoutIsTerminal func() bool
	stdinIsTerminal  func() bool
	// openTTY opens the controlling terminal for confirmation prompts, which
	// works under op run whatever stdin and stdout are.
	openTTY func() (io.ReadWriteCloser, error)

	baseURL    string
	httpClient *http.Client
	wait       func(ctx context.Context, d time.Duration) error
	now        func() time.Time
}

func main() {
	os.Exit(newApp().run(os.Args[1:]))
}

func newApp() *app {
	return &app{
		stdin:            os.Stdin,
		stdout:           os.Stdout,
		stderr:           os.Stderr,
		getenv:           os.Getenv,
		stdoutIsTerminal: func() bool { return isTerminal(os.Stdout) },
		stdinIsTerminal:  func() bool { return isTerminal(os.Stdin) },
		openTTY: func() (io.ReadWriteCloser, error) {
			return os.OpenFile("/dev/tty", os.O_RDWR, 0)
		},
		baseURL:    defaultBaseURL,
		httpClient: &http.Client{Timeout: requestTimeout},
		wait:       sleep,
		now:        time.Now,
	}
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// usageError exits with status 2. An empty message means the usage was
// already printed.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usagef(format string, args ...any) error {
	return &usageError{msg: fmt.Sprintf(format, args...)}
}

// run returns the exit status: 0 for success, 1 for errors and 2 for usage
// errors.
func (a *app) run(args []string) int {
	err := a.dispatch(args)
	var usageErr *usageError
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &usageErr):
		if usageErr.msg != "" {
			fmt.Fprintf(a.stderr, "aopctl: %s\n", usageErr.msg)
		}
		return 2
	default:
		fmt.Fprintf(a.stderr, "aopctl: %v\n", err)
		return 1
	}
}

func (a *app) dispatch(args []string) error {
	commands := map[string]func([]string) error{
		"ca create":      a.caCreate,
		"ca show":        a.caShow,
		"leaf issue":     a.leafIssue,
		"leaf associate": a.leafAssociate,
		"leaf status":    a.leafStatus,
		"leaf prune":     a.leafPrune,
	}
	if len(args) == 0 {
		fmt.Fprint(a.stderr, usageText)
		return &usageError{}
	}
	if isHelp(args[0]) {
		fmt.Fprint(a.stderr, usageText)
		return flag.ErrHelp
	}
	if len(args) >= 2 {
		if cmd, ok := commands[args[0]+" "+args[1]]; ok {
			return cmd(args[2:])
		}
	}
	if len(args) == 2 && isHelp(args[1]) && (args[0] == "ca" || args[0] == "leaf") {
		fmt.Fprint(a.stderr, usageText)
		return flag.ErrHelp
	}
	fmt.Fprint(a.stderr, usageText)
	return usagef("unknown command %q", strings.Join(args[:min(len(args), 2)], " "))
}

func isHelp(arg string) bool {
	return arg == "-h" || arg == "-help" || arg == "--help" || arg == "help"
}

func (a *app) flagSet(name, synopsis string) *flag.FlagSet {
	fs := flag.NewFlagSet("aopctl "+name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	fs.Usage = func() {
		fmt.Fprintf(a.stderr, "Usage: aopctl %s %s\n\nFlags:\n", name, synopsis)
		fs.PrintDefaults()
	}
	return fs
}

func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		// The flag package has printed the error and the usage.
		return &usageError{}
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return usagef("unexpected argument %q", fs.Arg(0))
	}
	return nil
}

// stringList is a repeatable flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func validateDays(days int) error {
	if days <= 0 {
		return usagef("--days must be positive, got %d", days)
	}
	return nil
}

func validateTimeout(timeout time.Duration) error {
	if timeout <= 0 {
		return usagef("--timeout must be positive, got %s", timeout)
	}
	return nil
}

func (a *app) requireEnv(name string) (string, error) {
	v := strings.TrimSpace(a.getenv(name))
	if v == "" {
		return "", fmt.Errorf("%s is not set", name)
	}
	return v, nil
}

func (a *app) cloudflare() (*cfClient, error) {
	token, err := a.requireEnv("CLOUDFLARE_API_TOKEN")
	if err != nil {
		return nil, err
	}
	zoneID, err := a.requireEnv("CLOUDFLARE_ZONE_ID")
	if err != nil {
		return nil, err
	}
	return &cfClient{baseURL: a.baseURL, token: token, zoneID: zoneID, http: a.httpClient}, nil
}
