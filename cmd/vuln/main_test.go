package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureApp writes a small module that funnels an HTTP request into a
// pretend-vulnerable symbol, and a local database whose advisory names that
// symbol. It returns the app and database directories.
func fixtureApp(t *testing.T) (appDir, dbDir string) {
	t.Helper()
	appDir = t.TempDir()
	dbDir = t.TempDir()

	write(t, filepath.Join(appDir, "go.mod"), "module example.com/vulnapp\n\ngo 1.24.4\n")
	write(t, filepath.Join(appDir, "main.go"), `package main

import "net/http"

func risky(q string) {}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		risky(r.URL.Query().Get("q"))
	})
	http.ListenAndServe(":8080", nil)
}
`)

	write(t, filepath.Join(dbDir, "index", "modules.json"),
		`[{"path":"example.com/vulnapp","vulns":[{"id":"GO-2099-0001"}]}]`)
	write(t, filepath.Join(dbDir, "ID", "GO-2099-0001.json"),
		`{"id":"GO-2099-0001","summary":"Injection in risky","affected":[{"package":{"ecosystem":"Go","name":"example.com/vulnapp"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}],"ecosystem_specific":{"imports":[{"path":"example.com/vulnapp","symbols":["risky"]}]}}],"database_specific":{"review_status":"REVIEWED"}}`)
	return appDir, dbDir
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRunTextReportsFindingAndExits3(t *testing.T) {
	app, db := fixtureApp(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"-C", app, "-db", db, "./..."}, &stdout, &stderr)

	if code != exitFindings {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitFindings, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "GO-2099-0001") {
		t.Errorf("output missing advisory id:\n%s", out)
	}
	if !strings.Contains(out, "TAINT") {
		t.Errorf("output missing taint tier:\n%s", out)
	}
}

func TestRunJSONFormat(t *testing.T) {
	app, db := fixtureApp(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"-C", app, "-db", db, "-format", "json", "./..."}, &stdout, &stderr)
	if code != exitFindings {
		t.Fatalf("exit code = %d, want %d", code, exitFindings)
	}
	var res struct {
		Findings []struct {
			OSV  string `json:"osv"`
			Tier int    `json:"tier"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, stdout.String())
	}
	if len(res.Findings) != 1 || res.Findings[0].OSV != "GO-2099-0001" {
		t.Fatalf("unexpected findings: %+v", res.Findings)
	}
}

func TestRunSARIFFormat(t *testing.T) {
	app, db := fixtureApp(t)
	var stdout, stderr bytes.Buffer
	run([]string{"-C", app, "-db", db, "-format", "sarif", "./..."}, &stdout, &stderr)
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						Region struct {
							StartLine   int `json:"startLine"`
							StartColumn int `json:"startColumn"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF: %v", err)
	}
	if log.Version != "2.1.0" {
		t.Errorf("SARIF version = %q, want 2.1.0", log.Version)
	}
	if len(log.Runs) == 0 || len(log.Runs[0].Results) == 0 {
		t.Fatal("SARIF has no results")
	}
	if got := log.Runs[0].Results[0].RuleID; got != "GO-2099-0001" {
		t.Errorf("SARIF ruleId = %q, want GO-2099-0001", got)
	}
	// The deepest trace position in the fixture is the risky() call on line 9
	// of main.go; a transposed line/column would report line 3 instead.
	if locs := log.Runs[0].Results[0].Locations; len(locs) > 0 {
		region := locs[0].PhysicalLocation.Region
		if region.StartLine != 9 {
			t.Errorf("SARIF startLine = %d, want 9 (column transposed?) startColumn = %d",
				region.StartLine, region.StartColumn)
		}
	} else {
		t.Error("SARIF result has no locations")
	}
}

func TestRunNoFindingsExits0(t *testing.T) {
	app := t.TempDir()
	db := t.TempDir()
	write(t, filepath.Join(app, "go.mod"), "module example.com/clean\n\ngo 1.24.4\n")
	write(t, filepath.Join(app, "main.go"), "package main\n\nfunc main() {}\n")
	write(t, filepath.Join(db, "index", "modules.json"), `[]`)

	var stdout, stderr bytes.Buffer
	code := run([]string{"-C", app, "-db", db, "./..."}, &stdout, &stderr)
	if code != exitNoFindings {
		t.Fatalf("exit code = %d, want %d", code, exitNoFindings)
	}
	if !strings.Contains(stdout.String(), "No known vulnerabilities") {
		t.Errorf("expected clean message, got:\n%s", stdout.String())
	}
}

func TestRunMinTierFiltersOut(t *testing.T) {
	// A module-level advisory filtered out by -min symbol yields no findings
	// and a zero exit.
	app := t.TempDir()
	db := t.TempDir()
	write(t, filepath.Join(app, "go.mod"), "module example.com/app\n\ngo 1.24.4\n")
	write(t, filepath.Join(app, "main.go"), "package main\n\nfunc main() {}\n")
	write(t, filepath.Join(db, "index", "modules.json"),
		`[{"path":"example.com/app","vulns":[{"id":"GO-2099-0002"}]}]`)
	write(t, filepath.Join(db, "ID", "GO-2099-0002.json"),
		`{"id":"GO-2099-0002","affected":[{"package":{"ecosystem":"Go","name":"example.com/app"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`)

	var stdout, stderr bytes.Buffer
	code := run([]string{"-C", app, "-db", db, "-min", "symbol", "./..."}, &stdout, &stderr)
	if code != exitNoFindings {
		t.Fatalf("exit code = %d, want %d (module finding filtered out)", code, exitNoFindings)
	}
}

func TestRunInvalidMinTierErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-min", "symbl", "./..."}, &stdout, &stderr)
	if code != exitError {
		t.Fatalf("exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr.String(), "invalid -min") {
		t.Errorf("stderr missing -min diagnostic:\n%s", stderr.String())
	}
}

func TestRunInvalidFormatErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-format", "xml", "./..."}, &stdout, &stderr)
	if code != exitError {
		t.Fatalf("exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr.String(), "unknown -format") {
		t.Errorf("stderr missing -format diagnostic:\n%s", stderr.String())
	}
}

func TestRunBadDatabasePathErrors(t *testing.T) {
	app := t.TempDir()
	write(t, filepath.Join(app, "go.mod"), "module example.com/app\n\ngo 1.24.4\n")
	write(t, filepath.Join(app, "main.go"), "package main\n\nfunc main() {}\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{"-C", app, "-db", filepath.Join(app, "does-not-exist"), "./..."}, &stdout, &stderr)
	if code != exitError {
		t.Fatalf("exit code = %d, want %d", code, exitError)
	}
}
