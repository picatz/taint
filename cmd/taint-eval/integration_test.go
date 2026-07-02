package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEndToEnd_LocalCheck exercises the harness against the committed
// fixtures and snapshots so future changes to normalization, manifest
// loading, or runner wiring surface as a test failure rather than
// silently drifting snapshots.
//
// The repo root is resolved by walking up from this file until go.mod
// is found, so the test does not depend on the test working directory.
func TestEndToEnd_LocalCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end requires building analyzer binaries")
	}
	repoRoot := findRepoRoot(t)
	sarifDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	args := []string{
		"check",
		"-manifest", filepath.Join(repoRoot, "testdata", "eval", "targets.yaml"),
		"-snapshots", filepath.Join(repoRoot, "testdata", "eval", "snapshots"),
		"-cache", t.TempDir(),
		"-repo", repoRoot,
		"-target", "local",
		"-sarif-dir", sarifDir,
	}
	if err := run(context.Background(), args, &stdout, &stderr); err != nil {
		t.Fatalf("check failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "local-clean: OK") {
		t.Fatalf("expected local-clean OK in output:\n%s", out)
	}
	if !strings.Contains(out, "local-sqli-positive: OK") {
		t.Fatalf("expected local-sqli-positive OK in output:\n%s", out)
	}
	if !strings.Contains(out, "local-cmdi-positive: OK") {
		t.Fatalf("expected local-cmdi-positive OK in output:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(sarifDir, "local-sqli-positive-sqli.sarif")); err != nil {
		t.Fatalf("expected SARIF report: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sarifDir, "local-cmdi-positive-cmdi.sarif")); err != nil {
		t.Fatalf("expected cmdi SARIF report: %v", err)
	}
}

// TestEndToEnd_ReportLocal exercises the report subcommand against the
// local fixtures. Every local positive fixture has an expect entry, so a
// correct run scores 6/6 recall with no false positives.
func TestEndToEnd_ReportLocal(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end requires building analyzer binaries")
	}
	repoRoot := findRepoRoot(t)

	var stdout, stderr bytes.Buffer
	args := []string{
		"report",
		"-manifest", filepath.Join(repoRoot, "testdata", "eval", "targets.yaml"),
		"-snapshots", filepath.Join(repoRoot, "testdata", "eval", "snapshots"),
		"-cache", t.TempDir(),
		"-repo", repoRoot,
		"-target", "local",
	}
	if err := run(context.Background(), args, &stdout, &stderr); err != nil {
		t.Fatalf("report failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"local-ptrv-positive: OK (1/1 expected findings)",
		"local-ssrf-positive: OK (1/1 expected findings)",
		"ANALYZER",
		"TOTAL",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("report output missing %q:\n%s", want, out)
		}
	}
}

// TestEndToEnd_List verifies the list subcommand renders expected counts
// pulled from the committed snapshots.
func TestEndToEnd_List(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end relies on full repo state")
	}
	repoRoot := findRepoRoot(t)

	var stdout, stderr bytes.Buffer
	args := []string{
		"list",
		"-manifest", filepath.Join(repoRoot, "testdata", "eval", "targets.yaml"),
		"-snapshots", filepath.Join(repoRoot, "testdata", "eval", "snapshots"),
	}
	if err := run(context.Background(), args, &stdout, &stderr); err != nil {
		t.Fatalf("list failed: %v\nstderr:\n%s", err, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"local-clean", "local-sqli-positive", "local-cmdi-positive", "sqli=1", "cmdi=1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("list output missing %q:\n%s", want, out)
		}
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod")
		}
		dir = parent
	}
}
