package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteSnapshotSARIF(t *testing.T) {
	dir := t.TempDir()
	snap := &Snapshot{
		Target: "local/sqli",
		Analyzers: map[string]AnalyzerResult{
			"sqli": {
				Findings: []Finding{{
					File:    "main.go",
					Line:    7,
					Column:  11,
					Message: "potential sql injection",
				}},
			},
		},
	}
	snap.normalize()

	if err := WriteSnapshotSARIF(dir, snap.Target, snap); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "local-sqli-sqli.sarif")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" {
		t.Fatalf("version = %q", doc.Version)
	}
	if got := doc.Runs[0].Results[0].RuleID; got != "sqli" {
		t.Fatalf("rule = %q", got)
	}
	if got := doc.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "main.go" {
		t.Fatalf("uri = %q", got)
	}
}
