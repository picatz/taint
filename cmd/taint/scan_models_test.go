package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const scanCustomModels = `package: example.com/scanmodels/api
sources:
  - call: example.com/scanmodels/api.Source
sinks:
  - method: example.com/scanmodels/api.Sink
    args: [0]
    kind: deliberately-not-the-selected-analyzer
sanitizers:
  - func: example.com/scanmodels/api.Clean
`

func scanModelFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, contents := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func scanModelFixture(t *testing.T) string {
	t.Helper()
	return scanModelFiles(t, map[string]string{
		"go.mod":     "module example.com/scanmodels\ngo 1.26.0\n",
		"api/api.go": "package api\nfunc Source() string { return \"input\" }\nfunc Sink(string) {}\nfunc Clean(s string) string { return s }\n",
		"main.go": `package main
import "example.com/scanmodels/api"
func main() {
 api.Sink(api.Source())
 api.Sink("safe")
 api.Sink(api.Clean(api.Source()))
}
`,
		"models/custom.yaml": scanCustomModels,
	})
}

func TestScanModelsValidationBeforeLoad(t *testing.T) {
	dir := scanModelFiles(t, map[string]string{
		"malformed.yaml":         "package: [\n",
		"invalid.yaml":           "package: example.com/a\nsources:\n  - field: Body\n",
		"invalid-summary.yaml":   "package: example.com/a\nsummaries:\n  - func: example.com/a.F\n    to: unknown\n",
		"directory/valid.yaml":   scanCustomModels,
		"directory/invalid.yaml": "package: [\n",
	})
	for _, format := range []string{"text", "json", "sarif"} {
		for _, tc := range []struct {
			name string
			args []string
			want string
		}{
			{"missing", []string{"-analyzers=logi", "-models=" + filepath.Join(dir, "missing.yaml")}, "reading models"},
			{"malformed", []string{"-analyzers=logi", "-models=" + filepath.Join(dir, "malformed.yaml")}, "-models:"},
			{"invalid", []string{"-analyzers=logi", "-models=" + filepath.Join(dir, "invalid.yaml")}, "-models:"},
			{"invalid-summary", []string{"-analyzers=logi", "-models=" + filepath.Join(dir, "invalid-summary.yaml")}, "-models:"},
			{"invalid-directory", []string{"-analyzers=logi", "-models=" + filepath.Join(dir, "directory")}, "-models:"},
			{"default-analyzers", []string{"-models="}, "requires exactly one"},
			{"multiple-analyzers", []string{"-analyzers=logi,sqli", "-models=missing.yaml"}, "requires exactly one"},
			{"zero-analyzers", []string{"-analyzers=,", "-models=missing.yaml"}, "requires exactly one"},
		} {
			t.Run(format+"/"+tc.name, func(t *testing.T) {
				var out, stderr bytes.Buffer
				args := append([]string{"-C=/does/not/exist", "-format=" + format}, tc.args...)
				code := runScan(context.Background(), args, &out, &stderr)
				if code != scanExitError || out.Len() != 0 || !strings.Contains(stderr.String(), tc.want) || strings.Contains(stderr.String(), "loading packages") {
					t.Fatalf("code=%d stdout=%s stderr=%s", code, &out, &stderr)
				}
			})
		}
	}
}

func scanModelReport(t *testing.T, dir, format string, extra ...string) (int, string, string) {
	t.Helper()
	var out, stderr bytes.Buffer
	args := append([]string{"-C", dir, "-format=" + format, "-analyzers=logi"}, extra...)
	code := runScan(context.Background(), args, &out, &stderr)
	return code, out.String(), stderr.String()
}

func scanModelJSON(t *testing.T, output string) []scanFindingJSON {
	t.Helper()
	var doc struct {
		Findings []scanFindingJSON `json:"findings"`
	}
	if err := json.Unmarshal([]byte(output), &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Findings
}

func TestScanModelsFormatsAndPaths(t *testing.T) {
	t.Setenv("GOWORK", "off")
	dir := scanModelFixture(t)
	// The source/sink declarations are imported, but their occurrences are in main.
	for _, scope := range []string{"legacy", "selected"} {
		for _, format := range []string{"text", "json", "sarif"} {
			t.Run(scope+"/"+format, func(t *testing.T) {
				var expected string
				for _, path := range []string{"models/custom.yaml", "models", filepath.Join(dir, "models/custom.yaml")} {
					code, out, stderr := scanModelReport(t, dir, format, "-scope="+scope, "-models="+path, "-analyzers=logi,logi")
					if code != scanExitFindings {
						t.Fatalf("code=%d out=%s stderr=%s", code, out, stderr)
					}
					if expected != "" && out != expected {
						t.Fatalf("path changed report: %s / %s", expected, out)
					}
					expected = out
				}
				switch format {
				case "text":
					if expected != "main.go:4:10: potential log injection (logi)\n" {
						t.Fatal(expected)
					}
				case "json":
					got := scanModelJSON(t, expected)
					want := []scanFindingJSON{{Analyzer: "logi", File: "main.go", Line: 4, Column: 10, Message: "potential log injection"}}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("got=%+v want=%+v", got, want)
					}
				case "sarif":
					var doc struct {
						Runs []struct {
							Results []struct {
								RuleID string `json:"ruleId"`
							} `json:"results"`
						} `json:"runs"`
					}
					if err := json.Unmarshal([]byte(expected), &doc); err != nil {
						t.Fatal(err)
					}
					if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 || doc.Runs[0].Results[0].RuleID != "logi/potential-log-injection" {
						t.Fatal(expected)
					}
				}
				code, out, stderr := scanModelReport(t, dir, format, "-scope="+scope, "-models=models", "-coverage")
				if code != scanExitFindings || out != expected || !strings.Contains(stderr, "SSA bodies") {
					t.Fatalf("coverage changed findings: %d %s %s", code, out, stderr)
				}
				for _, extra := range [][]string{nil, {"-models="}} {
					code, out, stderr = scanModelReport(t, dir, format, append([]string{"-scope=" + scope}, extra...)...)
					if code != scanExitClean {
						t.Fatalf("models leaked: %d %s %s", code, out, stderr)
					}
					if format != "text" && !json.Valid([]byte(out)) {
						t.Fatal(out)
					}
				}
			})
		}
	}
}

func TestScanModelsSourceSinkAndSanitizerControls(t *testing.T) {
	t.Setenv("GOWORK", "off")
	dir := scanModelFixture(t)
	for _, tc := range []struct {
		name, model string
		lines       []int
	}{
		{"source-only", "package: example.com/scanmodels/api\nsources:\n  - call: example.com/scanmodels/api.Source\n", nil},
		{"sink-only", "package: example.com/scanmodels/api\nsinks:\n  - method: example.com/scanmodels/api.Sink\n", nil},
		{"sanitizer", scanCustomModels, []int{4}},
		{"no-sanitizer", strings.Split(scanCustomModels, "sanitizers:")[0], []int{4, 6}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "control.yaml")
			if err := os.WriteFile(path, []byte(tc.model), 0600); err != nil {
				t.Fatal(err)
			}
			code, out, stderr := scanModelReport(t, dir, "json", "-scope=selected", "-bodies=same-module", "-max-body-packages=1", "-max-body-syntax-bytes=10000", "-models="+path)
			want := scanExitClean
			if len(tc.lines) > 0 {
				want = scanExitFindings
			}
			if code != want {
				t.Fatalf("code=%d out=%s stderr=%s", code, out, stderr)
			}
			var lines []int
			for _, f := range scanModelJSON(t, out) {
				lines = append(lines, f.Line)
			}
			if !reflect.DeepEqual(lines, tc.lines) {
				t.Fatalf("lines=%v want=%v out=%s", lines, tc.lines, out)
			}
		})
	}
}

func TestScanModelsSelectedScopeAndBodies(t *testing.T) {
	t.Setenv("GOWORK", "off")
	const api = "package api\nfunc Source() string {return \"input\"}\nfunc Sink(string){}\nfunc Clean(s string)string{return s}\n"
	const helper = `package helper
import "example.com/scanmodels/api"
func Identity(s string) string{return s}
func Constant(s string) string{return "safe"}
func OwnSource() string{return api.Source()}
func OwnSink(s string){api.Sink(s)}
func Sanitize(s string)string{return api.Clean(s)}
`
	dir := scanModelFiles(t, map[string]string{
		"go.mod": "module example.com/scanmodels\ngo 1.26.0\n", "api/api.go": api, "helper/helper.go": helper, "models.yaml": scanCustomModels,
		"caller/caller.go": `package caller
import("example.com/scanmodels/api";"example.com/scanmodels/helper")
func Direct(){api.Sink(api.Source())}
func Propagate(){api.Sink(helper.Identity(api.Source()))}
func Constant(){api.Sink(helper.Constant(api.Source()))}
func HelperSource(){api.Sink(helper.OwnSource())}
func HelperSink(){helper.OwnSink(api.Source())}
func Sanitized(){api.Sink(helper.Sanitize(api.Source()))}
`,
	})
	base := []string{"-scope=selected", "-models=models.yaml"}
	expanded := []string{"-bodies=same-module", "-max-body-packages=2", fmt.Sprintf("-max-body-syntax-bytes=%d", len(api)+len(helper))}
	for _, tc := range []struct {
		name                  string
		flags, patterns, want []string
	}{
		{"opaque", nil, []string{"./caller"}, []string{"caller/caller.go:3"}},
		{"same-module", expanded, []string{"./caller"}, []string{"caller/caller.go:3", "caller/caller.go:4"}},
		{"selected-helper", nil, []string{"./caller", "./helper"}, []string{"caller/caller.go:3", "caller/caller.go:4", "caller/caller.go:6", "helper/helper.go:6"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append(append(append([]string(nil), base...), tc.flags...), tc.patterns...)
			code, out, stderr := scanModelReport(t, dir, "json", args...)
			if code != scanExitFindings {
				t.Fatalf("code=%d out=%s stderr=%s", code, out, stderr)
			}
			var got []string
			for _, f := range scanModelJSON(t, out) {
				got = append(got, fmt.Sprintf("%s:%d", f.File, f.Line))
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got=%v want=%v out=%s", got, tc.want, out)
			}
		})
	}
	// A summary supplies propagation through an opaque helper without loading
	// its body or expanding source/sink occurrence scope.
	summary := scanCustomModels + "\n---\npackage: example.com/scanmodels/helper\nsummaries:\n  - func: example.com/scanmodels/helper.Identity\n    from: [0]\n    to: result\n"
	if err := os.WriteFile(filepath.Join(dir, "summary.yaml"), []byte(summary), 0600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := scanModelReport(t, dir, "json", "-scope=selected", "-models=summary.yaml", "./caller")
	findings := scanModelJSON(t, out)
	if code != scanExitFindings || len(findings) != 2 || findings[0].Line != 3 || findings[1].Line != 4 {
		t.Fatalf("summary: %d %s %s", code, out, stderr)
	}
	for _, limit := range []string{"-max-body-packages=1", fmt.Sprintf("-max-body-syntax-bytes=%d", len(api)+len(helper)-1)} {
		args := append(append(append([]string(nil), base...), expanded...), limit, "./caller")
		code, out, stderr := scanModelReport(t, dir, "json", args...)
		if code != scanExitError || out != "" || !strings.Contains(stderr, "same-module body budget exceeded") {
			t.Fatalf("budget bypassed: %d %s %s", code, out, stderr)
		}
	}
}

func TestScanModelsAddToBuiltins(t *testing.T) {
	t.Setenv("GOWORK", "off")
	dir := scanModelFixture(t)
	source := `package fixture
import ("log"; "net/http"; "example.com/scanmodels/api")
func Handler(r *http.Request) {
 log.Print(r.URL.Query().Get("q"))
 api.Sink(api.Source())
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		models bool
		lines  []int
	}{{false, []int{4}}, {true, []int{4, 5}}, {false, []int{4}}} {
		args := []string{"-scope=selected"}
		if tc.models {
			args = append(args, "-models=models")
		}
		code, out, stderr := scanModelReport(t, dir, "json", args...)
		if code != scanExitFindings {
			t.Fatalf("code=%d out=%s stderr=%s", code, out, stderr)
		}
		var lines []int
		for _, f := range scanModelJSON(t, out) {
			lines = append(lines, f.Line)
		}
		if !reflect.DeepEqual(lines, tc.lines) {
			t.Fatalf("models=%v got=%v want=%v out=%s", tc.models, lines, tc.lines, out)
		}
	}
}

func TestScanModelsAnalyzerSelection(t *testing.T) {
	t.Setenv("GOWORK", "off")
	dir := scanModelFixture(t)
	for _, analyzer := range []string{"cmdi", "logi", "ptrv", "sqli", "ssrf", "xss"} {
		t.Run(analyzer, func(t *testing.T) {
			code, out, stderr := scanModelReport(t, dir, "json", "-scope=selected", "-models=models", "-analyzers="+analyzer)
			if code != scanExitFindings {
				t.Fatalf("code=%d out=%s stderr=%s", code, out, stderr)
			}
			findings := scanModelJSON(t, out)
			if len(findings) != 1 || findings[0].Analyzer != analyzer || findings[0].Line != 4 {
				t.Fatalf("wrong analyzer attribution: %s", out)
			}
		})
	}
}

func TestScanModelsRelativeDirectoryAndFlagOrder(t *testing.T) {
	t.Setenv("GOWORK", "off")
	dir := scanModelFixture(t)
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(cwd, dir)
	if err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	code := runScan(context.Background(), []string{"-models=models/custom.yaml", "-analyzers=logi", "-format=json", "-C", relative}, &out, &stderr)
	if code != scanExitFindings || len(scanModelJSON(t, out.String())) != 1 {
		t.Fatalf("code=%d out=%s stderr=%s", code, &out, &stderr)
	}
	after, err := os.Getwd()
	if err != nil || after != cwd {
		t.Fatalf("cwd changed: %q -> %q (%v)", cwd, after, err)
	}
}
