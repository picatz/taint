package main

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNormalize_RelativeToRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("path layout differs on windows")
	}
	root := t.TempDir()
	raw := map[string][]AnalyzerDiagnosticJSON{
		"sqli": {
			{Posn: filepath.Join(root, "sub", "main.go") + ":12:17", Message: "potential sql injection"},
			{Posn: filepath.Join(root, "main.go") + ":1:1", Message: "potential sql injection"},
			// outside root: dropped
			{Posn: "/some/other/place/main.go:3:3", Message: "ignored"},
		},
	}
	out := Normalize(raw, root)
	res := out["sqli"]
	if res.Count != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", res.Count, res.Findings)
	}
	for _, f := range res.Findings {
		if filepath.IsAbs(f.File) {
			t.Fatalf("expected relative file, got %q", f.File)
		}
	}
}

func TestMergeAnalyzerJSON(t *testing.T) {
	doc := AnalyzerJSON{
		"pkg/a": {"sqli": []AnalyzerDiagnosticJSON{{Posn: "a.go:1:1", Message: "x"}}},
		"pkg/b": {"sqli": []AnalyzerDiagnosticJSON{{Posn: "b.go:2:2", Message: "y"}}},
	}
	merged := MergeAnalyzerJSON(doc)
	if got := len(merged["sqli"]); got != 2 {
		t.Fatalf("expected 2 sqli diagnostics, got %d", got)
	}
}

func TestParseAnalyzerJSON_LeadingNoise(t *testing.T) {
	raw := []byte("logi: logi flag -debug would conflict with driver; skipping\n{\"pkg\":{\"logi\":[{\"posn\":\"a.go:1:1\",\"message\":\"m\"}]}}")
	doc, warnings, err := parseAnalyzerJSON(raw)
	if err != nil {
		t.Fatalf("parseAnalyzerJSON: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if got := len(doc["pkg"]["logi"]); got != 1 {
		t.Fatalf("expected 1 finding, got %d", got)
	}
}

func TestParseAnalyzerJSON_PackageErrorEntries(t *testing.T) {
	raw := []byte(`{
		"pkg": {"sqli": [{"posn": "a.go:1:1", "message": "m"}]},
		"pkg [pkg.test]": {
			"buildssa": {"error": "analysis skipped due to errors in package"},
			"sqli": {"error": "failed prerequisites: buildssa@pkg [pkg.test]"}
		}
	}`)
	doc, warnings, err := parseAnalyzerJSON(raw)
	if err != nil {
		t.Fatalf("parseAnalyzerJSON: %v", err)
	}
	if got := len(doc["pkg"]["sqli"]); got != 1 {
		t.Fatalf("expected 1 finding from the healthy package, got %d", got)
	}
	if _, ok := doc["pkg [pkg.test]"]; ok {
		t.Fatal("failed package variant should not contribute diagnostics")
	}
	if len(warnings) != 2 {
		t.Fatalf("expected 2 warnings, got %v", warnings)
	}
	for _, w := range warnings {
		if !strings.Contains(w, "pkg [pkg.test]") {
			t.Fatalf("warning missing package id: %q", w)
		}
	}
}

func TestParseAnalyzerJSON_RejectsUnrecognizedEntry(t *testing.T) {
	raw := []byte(`{"pkg": {"sqli": {"bogus": true}}}`)
	if _, _, err := parseAnalyzerJSON(raw); err == nil {
		t.Fatal("expected error for unrecognized entry shape")
	}
}

func TestParseAnalyzerJSON_Empty(t *testing.T) {
	doc, warnings, err := parseAnalyzerJSON(nil)
	if err != nil {
		t.Fatalf("parseAnalyzerJSON: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if len(doc) != 0 {
		t.Fatalf("expected empty doc, got %+v", doc)
	}
}
