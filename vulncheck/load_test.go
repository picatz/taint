package vulncheck

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

func TestNormalizeGoVersion(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"go1.24.4", "go1.24.4"},
		{"go1.27", "go1.27"},
		{"devel go1.27-abcdef Mon Jan 2 15:04:05 2026 +0000", "go1.27"},
		{"devel go1.27-abcdef", "go1.27"},
		{"devel +abcdef", "devel +abcdef"}, // nothing extractable: unchanged
	}
	for _, tt := range tests {
		if got := normalizeGoVersion(tt.in); got != tt.want {
			t.Errorf("normalizeGoVersion(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestLoadBrokenPackageErrorSurfacedNotPrinted(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "go.mod"), "module example.com/broken\n\ngo 1.24.4\n")
	mustWrite(t, filepath.Join(dir, "main.go"), "package main\n\nfunc main() { undefinedIdent() }\n")

	// The load errors must arrive in the returned error, not on stderr:
	// capture the process stderr for the duration and require it stays empty.
	// Swapping os.Stderr means this test (and any sibling in this package)
	// must not run in parallel. The pipe is read concurrently so an
	// unexpectedly chatty Load fills no OS buffer and cannot deadlock us.
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = old }) // survive a panic inside Load
	capturedCh := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(r)
		capturedCh <- b
	}()
	_, loadErr := Load(t.Context(), LoadConfig{Dir: dir})
	w.Close()
	os.Stderr = old
	captured := <-capturedCh

	if loadErr == nil {
		t.Fatal("Load succeeded on a package that does not type-check")
	}
	if !strings.Contains(loadErr.Error(), "undefinedIdent") {
		t.Errorf("returned error does not carry the type error: %v", loadErr)
	}
	if len(captured) != 0 {
		t.Errorf("Load wrote to stderr: %q", captured)
	}
}

func TestBuildListSortedAndKeyed(t *testing.T) {
	pkgs := []*packages.Package{
		{PkgPath: "example.com/b/pkg", Module: &packages.Module{Path: "example.com/b", Version: "v1.0.0"}},
		{PkgPath: "example.com/a/pkg", Module: &packages.Module{Path: "example.com/a", Version: "v2.0.0"}},
		{PkgPath: "fmt"}, // stdlib usage pulls in the stdlib and toolchain pseudo-modules
	}
	got := buildList(pkgs, "go1.24.4")

	wantPaths := []string{"example.com/a", "example.com/b", "stdlib", "toolchain"}
	if len(got) != len(wantPaths) {
		t.Fatalf("buildList returned %d modules, want %d: %+v", len(got), len(wantPaths), got)
	}
	for i, want := range wantPaths {
		if got[i].Path != want {
			t.Errorf("modules[%d].Path = %q, want %q (deterministic sorted order)", i, got[i].Path, want)
		}
	}
	if got[2].Version != "go1.24.4" || got[3].Version != "go1.24.4" {
		t.Errorf("stdlib/toolchain versions = %q/%q, want go1.24.4", got[2].Version, got[3].Version)
	}
}
