// Command copy-plugin copies the plugin files from the container image root
// into a directory, so an init container can install them into a volume that
// Traefik loads as a local plugin.
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// pluginFiles are the files Traefik needs to load the plugin.
var pluginFiles = []string{".traefik.yml", "go.mod", "cloudflare_origin.go"}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: copy-plugin <dest>")
		os.Exit(2)
	}
	if err := run("/", os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "copy-plugin: %v\n", err)
		os.Exit(1)
	}
}

// run copies pluginFiles from src into the existing directory dst,
// overwriting files from an earlier run. It checks every source file before
// writing, so an incomplete source copies nothing.
func run(src, dst string) error {
	info, err := os.Stat(dst) //nolint:gosec // dst is the destination the operator passes by design.
	if err != nil {
		return fmt.Errorf("destination: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("destination %s is not a directory", dst)
	}

	for _, name := range pluginFiles {
		info, err := os.Stat(filepath.Join(src, name))
		if err != nil {
			return fmt.Errorf("source: %w", err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("source %s is not a regular file", filepath.Join(src, name))
		}
	}

	for _, name := range pluginFiles {
		target := filepath.Join(dst, name)
		if err := copyFile(filepath.Join(src, name), target); err != nil {
			return err
		}
		fmt.Printf("copied %s\n", target)
	}
	return nil
}

func copyFile(from, to string) error {
	data, err := os.ReadFile(from) //nolint:gosec // from is a fixed plugin file under src.
	if err != nil {
		return err
	}
	if err := os.WriteFile(to, data, 0o644); err != nil { //nolint:gosec // Plugin files are public source.
		return err
	}
	// WriteFile keeps the mode of an existing file and applies the umask to a
	// new one. Set 0644 explicitly so Traefik can read the file as any user.
	return os.Chmod(to, 0o644) //nolint:gosec // As above.
}
