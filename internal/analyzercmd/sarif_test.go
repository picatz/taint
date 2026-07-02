package analyzercmd

import (
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
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
	rule := log.Runs[0].Tool.Driver.Rules[0]
	if got := rule.HelpURI; got != "https://cwe.mitre.org/data/definitions/89.html" {
		t.Fatalf("help URI = %q", got)
	}
	if got := result.Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "main.go" {
		t.Fatalf("artifact URI = %q", got)
	}
	region := result.Locations[0].PhysicalLocation.Region
	if region.StartLine != 9 || region.StartColumn != 10 {
		t.Fatalf("region = %#v", region)
	}

	// GitHub code scanning metadata: security-severity must be a numeric
	// string in [0.1, 10.0], tags must include "security" and a CWE tag,
	// help.markdown must be populated (GitHub prefers it over help.text),
	// and defaultConfiguration.level/precision must be set.
	if got := rule.Properties.SecuritySeverity; got != "8.8" {
		t.Fatalf("security-severity = %q", got)
	}
	if sev, err := strconv.ParseFloat(rule.Properties.SecuritySeverity, 64); err != nil || sev < 0.1 || sev > 10.0 {
		t.Fatalf("security-severity %q not a numeric string in [0.1, 10.0]: %v", rule.Properties.SecuritySeverity, err)
	}
	if got := rule.Properties.Tags; len(got) < 2 || got[0] != "security" || got[1] != "external/cwe/cwe-89" {
		t.Fatalf("tags = %#v", got)
	}
	if got := rule.Properties.Precision; got == "" {
		t.Fatalf("precision is empty")
	}
	if got := rule.DefaultConfiguration.Level; got == "" {
		t.Fatalf("defaultConfiguration.level is empty")
	}
	if got := rule.Help.Markdown; got == "" {
		t.Fatalf("help.markdown is empty")
	}
	if got := rule.Help.Text; got == "" {
		t.Fatalf("help.text is empty")
	}
	if result.Level == "" {
		t.Fatalf("result level is empty")
	}
}

func TestSARIFRuleStructFieldsOmitWhenZero(t *testing.T) {
	// Regression test for the encoding/json "omitempty is a no-op on struct
	// fields" gotcha: a bare SARIFRule (as produced for an unknown rule with
	// no metadata) should not serialize empty shortDescription/
	// fullDescription/help/defaultConfiguration/properties objects.
	rule := SARIFRule{ID: "example"}
	b, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"shortDescription", "fullDescription", "help", "defaultConfiguration", "properties"} {
		if _, ok := doc[field]; ok {
			t.Fatalf("expected zero-value %q to be omitted, got %s", field, b)
		}
	}

	region := SARIFPhysicalLocation{ArtifactLocation: SARIFArtifactLocation{URI: "main.go"}}
	rb, err := json.Marshal(region)
	if err != nil {
		t.Fatal(err)
	}
	var rdoc map[string]json.RawMessage
	if err := json.Unmarshal(rb, &rdoc); err != nil {
		t.Fatal(err)
	}
	if _, ok := rdoc["region"]; ok {
		t.Fatalf("expected zero-value region to be omitted, got %s", rb)
	}
}

func TestSARIFCommandInjectionMetadata(t *testing.T) {
	root := t.TempDir()
	posn := filepath.Join(root, "main.go") + ":12:2"
	doc := analyzerJSON{
		"example.com/app": {
			"cmdi": {{Posn: posn, Message: "potential command injection"}},
		},
	}

	log := SARIFLogFromAnalyzerJSON(&analysis.Analyzer{Name: "cmdi", Doc: "finds potential command injection issues"}, doc, root)
	result := log.Runs[0].Results[0]
	if got := result.RuleID; got != "cmdi/potential-command-injection" {
		t.Fatalf("rule ID = %q", got)
	}
	if result.PartialFingerprints["taint/v1"] == "" {
		t.Fatalf("missing partial fingerprint: %#v", result.PartialFingerprints)
	}
	shifted := SARIFLogFromFindings("cmdi", "finds potential command injection issues", []Finding{{
		RuleID:  "cmdi",
		URI:     "main.go",
		Line:    99,
		Column:  7,
		Message: "potential command injection",
	}})
	if got, want := shifted.Runs[0].Results[0].PartialFingerprints["taint/v1"], result.PartialFingerprints["taint/v1"]; got != want {
		t.Fatalf("fingerprint changed after line movement: got %q want %q", got, want)
	}
	rule := log.Runs[0].Tool.Driver.Rules[0]
	if got := rule.HelpURI; got != "https://cwe.mitre.org/data/definitions/78.html" {
		t.Fatalf("help URI = %q", got)
	}
	if got := rule.Properties.Tags; len(got) != 2 || got[1] != "external/cwe/cwe-78" {
		t.Fatalf("tags = %#v", got)
	}
	if got := rule.Properties.SecuritySeverity; got != "9.8" {
		t.Fatalf("security-severity = %q", got)
	}
	if sev, err := strconv.ParseFloat(rule.Properties.SecuritySeverity, 64); err != nil || sev < 0.1 || sev > 10.0 {
		t.Fatalf("security-severity %q not a numeric string in [0.1, 10.0]: %v", rule.Properties.SecuritySeverity, err)
	}
	if got := rule.Properties.Precision; got == "" {
		t.Fatalf("precision is empty")
	}
	if got := rule.DefaultConfiguration.Level; got != "error" {
		t.Fatalf("defaultConfiguration.level = %q, want error", got)
	}
	if got := result.Level; got != "error" {
		t.Fatalf("result level = %q, want error", got)
	}
	if got := rule.Help.Markdown; got == "" {
		t.Fatalf("help.markdown is empty")
	}
}

// TestSARIFAllRuleMetadataComplete ensures every known rule ID carries the
// full set of GitHub code scanning metadata: a numeric security-severity in
// [0.1, 10.0], "security" plus a CWE tag, non-empty help.markdown/help.text,
// a non-empty precision, and a valid SARIF level.
func TestSARIFAllRuleMetadataComplete(t *testing.T) {
	ruleIDs := []string{
		"sqli/potential-sql-injection",
		"logi/potential-log-injection",
		"cmdi/potential-command-injection",
		"xss/potential-xss",
		"ptrv/potential-path-traversal",
		"ssrf/potential-server-side-request-forgery",
	}
	validLevels := map[string]bool{"error": true, "warning": true, "note": true}
	for _, id := range ruleIDs {
		meta := ruleMetadata(id)
		t.Run(id, func(t *testing.T) {
			sev, err := strconv.ParseFloat(meta.securitySeverity, 64)
			if err != nil {
				t.Fatalf("security-severity %q is not numeric: %v", meta.securitySeverity, err)
			}
			if sev < 0.1 || sev > 10.0 {
				t.Fatalf("security-severity %q out of [0.1, 10.0] range", meta.securitySeverity)
			}
			if len(meta.tags) < 2 || meta.tags[0] != "security" {
				t.Fatalf("tags = %#v, want first tag %q", meta.tags, "security")
			}
			hasCWETag := false
			for _, tag := range meta.tags {
				if strings.HasPrefix(tag, "external/cwe/cwe-") {
					hasCWETag = true
				}
			}
			if !hasCWETag {
				t.Fatalf("tags = %#v missing external/cwe/cwe-NNN tag", meta.tags)
			}
			if meta.precision == "" {
				t.Fatalf("precision is empty")
			}
			if !validLevels[meta.level] {
				t.Fatalf("level = %q is not a valid SARIF level", meta.level)
			}
			if meta.helpMarkdown == "" {
				t.Fatalf("helpMarkdown is empty")
			}
			if meta.helpURI == "" {
				t.Fatalf("helpURI is empty")
			}
			if meta.name == "" {
				t.Fatalf("name is empty")
			}
		})
	}
}
