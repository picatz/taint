package main

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestSplitPosn(t *testing.T) {
	cases := []struct {
		in     string
		path   string
		line   int
		column int
	}{
		{"/abs/foo/main.go:12:17", "/abs/foo/main.go", 12, 17},
		{"main.go:5", "main.go", 5, 0},
		{"only/path", "only/path", 0, 0},
		{"", "", 0, 0},
	}
	for _, tc := range cases {
		path, line, col := splitPosn(tc.in)
		if path != tc.path || line != tc.line || col != tc.column {
			t.Errorf("splitPosn(%q) = (%q, %d, %d), want (%q, %d, %d)",
				tc.in, path, line, col, tc.path, tc.line, tc.column)
		}
	}
}

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
	doc, err := parseAnalyzerJSON(raw)
	if err != nil {
		t.Fatalf("parseAnalyzerJSON: %v", err)
	}
	if got := len(doc["pkg"]["logi"]); got != 1 {
		t.Fatalf("expected 1 finding, got %d", got)
	}
}

func TestParseAnalyzerJSON_Empty(t *testing.T) {
	doc, err := parseAnalyzerJSON(nil)
	if err != nil {
		t.Fatalf("parseAnalyzerJSON: %v", err)
	}
	if len(doc) != 0 {
		t.Fatalf("expected empty doc, got %+v", doc)
	}
}
