package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

func TestSARIFOutputEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end requires go run")
	}
	repoRoot := findRepoRoot(t)
	out := filepath.Join(t.TempDir(), "cmdi.sarif")

	cmd := exec.Command("go", "run", "./cmd/cmdi", "-sarif-output", out, "./command/injection/testdata/src/shell")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "GOCACHE="+filepath.Join(t.TempDir(), "gocache"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go run cmdi -sarif-output: %v\n%s", err, output)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID                   string `json:"id"`
						HelpURI              string `json:"helpUri"`
						DefaultConfiguration struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
						Help struct {
							Text     string `json:"text"`
							Markdown string `json:"markdown"`
						} `json:"help"`
						Properties struct {
							Tags             []string `json:"tags"`
							Precision        string   `json:"precision"`
							SecuritySeverity string   `json:"security-severity"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" {
		t.Fatalf("version = %q", doc.Version)
	}
	if got := doc.Runs[0].Tool.Driver.Name; got != "cmdi" {
		t.Fatalf("driver name = %q", got)
	}
	if got := len(doc.Runs[0].Results); got != 2 {
		t.Fatalf("results = %d, want 2", got)
	}
	if got := doc.Runs[0].Results[0].RuleID; got != "cmdi/potential-command-injection" {
		t.Fatalf("rule = %q", got)
	}

	if got := len(doc.Runs[0].Tool.Driver.Rules); got != 1 {
		t.Fatalf("rules = %d, want 1", got)
	}
	rule := doc.Runs[0].Tool.Driver.Rules[0]
	if rule.ID != "cmdi/potential-command-injection" {
		t.Fatalf("rule ID = %q", rule.ID)
	}
	if sev, err := strconv.ParseFloat(rule.Properties.SecuritySeverity, 64); err != nil || sev < 0.1 || sev > 10.0 {
		t.Fatalf("security-severity = %q (parse err: %v)", rule.Properties.SecuritySeverity, err)
	}
	if len(rule.Properties.Tags) < 2 || rule.Properties.Tags[0] != "security" || rule.Properties.Tags[1] != "external/cwe/cwe-78" {
		t.Fatalf("tags = %#v", rule.Properties.Tags)
	}
	if rule.Properties.Precision == "" {
		t.Fatalf("precision is empty")
	}
	if rule.DefaultConfiguration.Level == "" {
		t.Fatalf("defaultConfiguration.level is empty")
	}
	if rule.Help.Markdown == "" {
		t.Fatalf("help.markdown is empty")
	}
	if doc.Runs[0].Results[0].Level == "" {
		t.Fatalf("result level is empty")
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
