package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Use real Go builds of tiny commands to exercise source freshness without
// rebuilding the full analyzers. A shared dependency models changes outside
// cmd/, which a command-only timestamp or Git revision cache key would miss.
func TestBuildBinariesFreshSource(t *testing.T) {
	repo := t.TempDir()
	cache := CacheDir(t.TempDir())
	write := func(path, content string) {
		t.Helper()
		path = filepath.Join(repo, path)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOWORK", "off")
	t.Setenv("GOFLAGS", os.Getenv("GOFLAGS")+" -buildvcs=false")
	write("go.mod", "module github.com/picatz/taint\n\ngo 1.26.0\n")
	names := []string{"sqli", "logi", "cmdi", "xss", "ptrv", "ssrf", "taint"}
	for _, name := range names {
		write("cmd/"+name+"/main.go", `package main
import ("fmt"; "github.com/picatz/taint/shared")
func main() { fmt.Print(shared.Value) }
`)
	}
	write("shared/value.go", "package shared\nconst Value = \"first\"\n")
	// Legacy cached binaries must neither be trusted nor deleted by a run.
	legacy := filepath.Join(string(cache), "bin", "sqli"+exeSuffix())
	if err := os.MkdirAll(filepath.Dir(legacy), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte("stale"), 0o755); err != nil {
		t.Fatal(err)
	}
	first, err := buildBinaries(context.Background(), cache, repo)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(first.cleanup)
	check := func(b binaries, want string) {
		t.Helper()
		for _, name := range names {
			path := b.taint
			if name != "taint" {
				var err error
				path, err = b.analyzer(name)
				if err != nil {
					t.Fatal(err)
				}
			}
			out, err := exec.Command(path).CombinedOutput()
			if err != nil || string(out) != want {
				t.Fatalf("%s: output %q, error %v; want %q", name, out, err, want)
			}
		}
	}
	check(first, "first")
	write("shared/value.go", "package shared\nconst Value = \"second\"\n")
	second, err := buildBinaries(context.Background(), cache, repo)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(second.cleanup)
	check(second, "second")
	// A second invocation using the same cache must not alter a still-running
	// invocation's tools, even when the requested source has changed.
	check(first, "first")
	if first.taint == second.taint {
		t.Fatal("invocations share executable paths")
	}
	if _, err := second.analyzer("taint"); err == nil {
		t.Fatal("taint is not a per-package analyzer")
	}
	if _, err := second.analyzer("unknown"); err == nil {
		t.Fatal("unknown analyzer accepted")
	}
	first.cleanup()
	if _, err := os.Stat(filepath.Dir(first.taint)); !os.IsNotExist(err) {
		t.Fatalf("first directory not removed: %v", err)
	}
	check(second, "second")
	second.cleanup()
	// A broken current source must fail, never fall back to old executables.
	write("shared/value.go", "package shared\nconst Value =\n")
	failed, err := buildBinaries(context.Background(), cache, repo)
	if err == nil || !strings.Contains(err.Error(), "go build github.com/picatz/taint/cmd/") {
		t.Fatalf("expected build error, got %v", err)
	}
	if failed.analyzer != nil || failed.taint != "" {
		t.Fatal("failed build exposed binaries")
	}
	entries, err := os.ReadDir(string(cache))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "bin" {
		t.Fatalf("temporary build directories leaked: %v", entries)
	}
	if got, err := os.ReadFile(legacy); err != nil || string(got) != "stale" {
		t.Fatalf("legacy cache modified: %q, %v", got, err)
	}
}
