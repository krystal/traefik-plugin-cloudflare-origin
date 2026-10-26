package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name string
		// setup prepares src and dst and returns the destination to pass to run.
		setup   func(t *testing.T, src, dst string) string
		wantErr bool
	}{
		{
			name:  "copies into an empty directory",
			setup: func(_ *testing.T, _, dst string) string { return dst },
		},
		{
			name: "overwrites an earlier copy",
			setup: func(t *testing.T, _, dst string) string {
				writeFile(t, filepath.Join(dst, "go.mod"), "stale contents, longer than the new file", 0o600)
				return dst
			},
		},
		{
			name: "source file missing",
			setup: func(t *testing.T, src, dst string) string {
				if err := os.Remove(filepath.Join(src, "cloudflare_origin.go")); err != nil {
					t.Fatal(err)
				}
				return dst
			},
			wantErr: true,
		},
		{
			name: "source file is a directory",
			setup: func(t *testing.T, src, dst string) string {
				path := filepath.Join(src, "go.mod")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				return dst
			},
			wantErr: true,
		},
		{
			name:    "destination missing",
			setup:   func(_ *testing.T, _, dst string) string { return filepath.Join(dst, "missing") },
			wantErr: true,
		},
		{
			name: "destination is a file",
			setup: func(t *testing.T, _, _ string) string {
				path := filepath.Join(t.TempDir(), "file")
				writeFile(t, path, "", 0o600)
				return path
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, dst := t.TempDir(), t.TempDir()
			for _, name := range pluginFiles {
				writeFile(t, filepath.Join(src, name), "contents of "+name, 0o600)
			}

			err := run(src, tt.setup(t, src, dst))

			if tt.wantErr {
				if err == nil {
					t.Fatal("run succeeded, want an error")
				}
				entries, err := os.ReadDir(dst)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 0 {
					t.Errorf("destination holds %d entries after a failed run, want none", len(entries))
				}
				return
			}
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			for _, name := range pluginFiles {
				want, err := os.ReadFile(filepath.Join(src, name)) //nolint:gosec // name comes from the fixed pluginFiles list.
				if err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(filepath.Join(dst, name)) //nolint:gosec // As above.
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Errorf("%s = %q, want %q", name, got, want)
				}
				info, err := os.Stat(filepath.Join(dst, name))
				if err != nil {
					t.Fatal(err)
				}
				if mode := info.Mode().Perm(); mode != 0o644 {
					t.Errorf("%s mode = %o, want 644", name, mode)
				}
			}
		})
	}
}

func writeFile(t *testing.T, path, contents string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
}
