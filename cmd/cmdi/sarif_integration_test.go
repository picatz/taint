package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
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
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
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
