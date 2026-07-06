package main

import (
	"bytes"
	"encoding/json"
	"go/token"
	"strings"
	"testing"
)

func TestSelectScanDetectors(t *testing.T) {
	t.Run("empty selects all in registry order", func(t *testing.T) {
		got, err := selectScanDetectors("")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(scanDetectors) {
			t.Fatalf("selected %d, want all %d", len(got), len(scanDetectors))
		}
		for i, d := range got {
			if d.name != scanDetectors[i].name {
				t.Errorf("position %d = %q, want %q", i, d.name, scanDetectors[i].name)
			}
		}
	})

	t.Run("subset keeps registry order regardless of input order", func(t *testing.T) {
		got, err := selectScanDetectors("xss, cmdi")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0].name != "cmdi" || got[1].name != "xss" {
			t.Fatalf("got %v, want [cmdi xss] in registry order", names(got))
		}
	})

	t.Run("unknown analyzer errors", func(t *testing.T) {
		if _, err := selectScanDetectors("sqli,bogus"); err == nil {
			t.Fatal("expected an error for an unknown analyzer")
		}
	})
}

func names(ds []scanDetector) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.name
	}
	return out
}

func TestRelPath(t *testing.T) {
	tests := []struct {
		path, root, want string
	}{
		{"/app/pkg/a.go", "/app", "pkg/a.go"},
		{"/other/a.go", "/app", "/other/a.go"}, // outside root: absolute
		{"/app/a.go", "", "/app/a.go"},         // no root: unchanged
	}
	for _, tt := range tests {
		if got := relPath(tt.path, tt.root); got != tt.want {
			t.Errorf("relPath(%q, %q) = %q, want %q", tt.path, tt.root, got, tt.want)
		}
	}
}

func TestSortScanFindings(t *testing.T) {
	findings := []scanFinding{
		{Analyzer: "xss", Position: token.Position{Filename: "b.go", Line: 1}},
		{Analyzer: "sqli", Position: token.Position{Filename: "a.go", Line: 9}},
		{Analyzer: "sqli", Position: token.Position{Filename: "a.go", Line: 2}},
	}
	sortScanFindings(findings)
	if findings[0].Position.Filename != "a.go" || findings[0].Position.Line != 2 {
		t.Errorf("first = %+v, want a.go:2", findings[0].Position)
	}
	if findings[2].Position.Filename != "b.go" {
		t.Errorf("last = %+v, want b.go", findings[2].Position)
	}
}

func TestWriteScanText(t *testing.T) {
	var buf bytes.Buffer
	if err := writeScanText(&buf, nil, "/app"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No taint issues found") {
		t.Errorf("empty findings text = %q", buf.String())
	}

	buf.Reset()
	f := []scanFinding{{Analyzer: "sqli", Position: token.Position{Filename: "/app/x.go", Line: 3, Column: 5}, Message: "potential sql injection"}}
	if err := writeScanText(&buf, f, "/app"); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "x.go:3:5: potential sql injection (sqli)\n" {
		t.Errorf("text = %q", got)
	}
}

func TestWriteScanJSON(t *testing.T) {
	var buf bytes.Buffer
	f := []scanFinding{{Analyzer: "cmdi", Position: token.Position{Filename: "/app/x.go", Line: 9, Column: 2}, Message: "potential command injection"}}
	if err := writeScanJSON(&buf, f, "/app"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []scanFindingJSON `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(doc.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(doc.Findings))
	}
	got := doc.Findings[0]
	if got.Analyzer != "cmdi" || got.File != "x.go" || got.Line != 9 || got.Column != 2 {
		t.Errorf("finding = %+v", got)
	}
}

func TestWriteScanSARIFRuleID(t *testing.T) {
	// A whole-program finding must carry the same SARIF rule id as the
	// per-package binary, so it has one identity across both tools.
	var buf bytes.Buffer
	f := []scanFinding{{Analyzer: "sqli", Position: token.Position{Filename: "/app/x.go", Line: 3, Column: 5}, Message: "potential sql injection"}}
	if err := writeScanSARIF(&buf, f, "/app"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "sqli/potential-sql-injection") {
		t.Errorf("SARIF missing detailed rule id:\n%s", buf.String())
	}
}
