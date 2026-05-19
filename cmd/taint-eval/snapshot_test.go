package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSnapshotRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.json")
	snap := &Snapshot{
		Target: "a",
		Kind:   KindLocal,
		Source: "fixtures/a",
		Analyzers: map[string]AnalyzerResult{
			"sqli": {Findings: []Finding{
				{File: "z.go", Line: 1, Column: 1, Message: "potential sql injection"},
				{File: "a.go", Line: 1, Column: 1, Message: "potential sql injection"},
			}},
		},
	}
	if err := WriteSnapshot(path, snap); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}
	got, err := LoadSnapshot(path)
	if err != nil {
		t.Fatalf("LoadSnapshot: %v", err)
	}
	res := got.Analyzers["sqli"]
	if res.Count != 2 {
		t.Fatalf("count: got %d want 2", res.Count)
	}
	// Sorted by file path, so a.go comes first.
	if res.Findings[0].File != "a.go" {
		t.Fatalf("expected findings sorted by file, got %s first", res.Findings[0].File)
	}
}

func TestSnapshotEmptyFindingsIsArray(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")
	snap := &Snapshot{
		Target:    "empty",
		Kind:      KindLocal,
		Analyzers: map[string]AnalyzerResult{"sqli": {}},
	}
	if err := WriteSnapshot(path, snap); err != nil {
		t.Fatal(err)
	}
	raw, err := readFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "\"findings\": null") {
		t.Fatalf("expected findings to serialize as [], got %s", raw)
	}
	if !strings.Contains(raw, "\"findings\": []") {
		t.Fatalf("expected findings: [] in output: %s", raw)
	}
}

func TestDiffSnapshots(t *testing.T) {
	expected := &Snapshot{
		Analyzers: map[string]AnalyzerResult{
			"sqli": {Findings: []Finding{
				{File: "a.go", Line: 1, Column: 1, Message: "potential sql injection"},
				{File: "b.go", Line: 2, Column: 3, Message: "potential sql injection"},
			}},
			"logi": {Findings: []Finding{}},
		},
	}
	actual := &Snapshot{
		Analyzers: map[string]AnalyzerResult{
			"sqli": {Findings: []Finding{
				{File: "a.go", Line: 1, Column: 1, Message: "potential sql injection"},
				{File: "c.go", Line: 9, Column: 9, Message: "potential sql injection"},
			}},
			"logi": {Findings: []Finding{}},
		},
	}
	expected.normalize()
	actual.normalize()
	diffs := DiffSnapshots("t", expected, actual)
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d (%+v)", len(diffs), diffs)
	}
	d := diffs[0]
	if d.Analyzer != "sqli" {
		t.Fatalf("expected sqli diff, got %s", d.Analyzer)
	}
	if len(d.Missing) != 1 || d.Missing[0].File != "b.go" {
		t.Fatalf("missing: %+v", d.Missing)
	}
	if len(d.Unexpected) != 1 || d.Unexpected[0].File != "c.go" {
		t.Fatalf("unexpected: %+v", d.Unexpected)
	}
	out := FormatDiffs(diffs)
	if !strings.Contains(out, "drift in target=t") {
		t.Fatalf("FormatDiffs missing header: %s", out)
	}
	if !strings.Contains(out, "expected but missing") || !strings.Contains(out, "unexpected finding") {
		t.Fatalf("FormatDiffs missing detail: %s", out)
	}
}

func TestDiffSnapshots_NoDriftWhenEqual(t *testing.T) {
	snap := &Snapshot{
		Analyzers: map[string]AnalyzerResult{
			"sqli": {Findings: []Finding{{File: "a.go", Line: 1, Column: 1, Message: "m"}}},
		},
	}
	snap.normalize()
	if diffs := DiffSnapshots("t", snap, snap); len(diffs) != 0 {
		t.Fatalf("expected no drift, got %+v", diffs)
	}
}

func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
