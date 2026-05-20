package analyzercmd

import (
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/analysis"
)

func TestParseSARIFArgs(t *testing.T) {
	cfg, err := parseSARIFArgs([]string{"-sarif-output", "out.sarif", "-json", "-callgraph=vta", "./..."})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.enabled {
		t.Fatal("expected SARIF mode")
	}
	if cfg.output != "out.sarif" {
		t.Fatalf("output = %q", cfg.output)
	}
	wantArgs := []string{"-callgraph=vta", "./..."}
	if len(cfg.args) != len(wantArgs) {
		t.Fatalf("args = %#v, want %#v", cfg.args, wantArgs)
	}
	for i := range wantArgs {
		if cfg.args[i] != wantArgs[i] {
			t.Fatalf("args = %#v, want %#v", cfg.args, wantArgs)
		}
	}
}

func TestParseAnalyzerJSONAllowsLeadingNoise(t *testing.T) {
	doc, err := parseAnalyzerJSON([]byte("warning\n{\"pkg\":{\"sqli\":[{\"posn\":\"main.go:7:11\",\"message\":\"m\"}]}}"))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(doc["pkg"]["sqli"]); got != 1 {
		t.Fatalf("diagnostics = %d, want 1", got)
	}
}

func TestSARIFLogFromAnalyzerJSON(t *testing.T) {
	root := t.TempDir()
	posn := filepath.Join(root, "main.go") + ":9:10"
	doc := analyzerJSON{
		"example.com/app": {
			"sqli": {{Posn: posn, Message: "potential sql injection"}},
		},
	}

	log := SARIFLogFromAnalyzerJSON(&analysis.Analyzer{Name: "sqli", Doc: "finds sql"}, doc, root)
	if log.Version != "2.1.0" {
		t.Fatalf("SARIF version = %q", log.Version)
	}
	if got := log.Runs[0].Tool.Driver.Name; got != "sqli" {
		t.Fatalf("driver name = %q", got)
	}
	result := log.Runs[0].Results[0]
	if got := result.RuleID; got != "sqli/potential-sql-injection" {
		t.Fatalf("rule ID = %q", got)
	}
	if result.PartialFingerprints["taint/v1"] == "" {
		t.Fatalf("missing partial fingerprint: %#v", result.PartialFingerprints)
	}
	shifted := SARIFLogFromFindings("sqli", "finds sql", []Finding{{
		RuleID:  "sqli",
		URI:     "main.go",
		Line:    42,
		Column:  99,
		Message: "potential sql injection",
	}})
	if got, want := shifted.Runs[0].Results[0].PartialFingerprints["taint/v1"], result.PartialFingerprints["taint/v1"]; got != want {
		t.Fatalf("fingerprint changed after line movement: got %q want %q", got, want)
	}
	if got := log.Runs[0].Tool.Driver.Rules[0].HelpURI; got != "https://cwe.mitre.org/data/definitions/89.html" {
		t.Fatalf("help URI = %q", got)
	}
	if got := result.Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "main.go" {
		t.Fatalf("artifact URI = %q", got)
	}
	region := result.Locations[0].PhysicalLocation.Region
	if region.StartLine != 9 || region.StartColumn != 10 {
		t.Fatalf("region = %#v", region)
	}
}
