package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"go/token"
	"io"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/picatz/taint"
	cmdi "github.com/picatz/taint/command/injection"
	ptrv "github.com/picatz/taint/command/pathtraversal"
	"github.com/picatz/taint/internal/analyzercmd"
	"github.com/picatz/taint/internal/wholeprogram"
	logi "github.com/picatz/taint/log/injection"
	ssrf "github.com/picatz/taint/network/ssrf"
	sqli "github.com/picatz/taint/sql/injection"
	"github.com/picatz/taint/xss"
	"golang.org/x/tools/go/callgraph"
)

// detectorCheck runs one detector over a whole-program call graph. It is the
// engine seam the six per-package analyzers and this whole-program scan share,
// so a flow that crosses a package boundary, invisible to a per-package pass,
// is found here.
type detectorCheck func(ctx context.Context, cg *callgraph.Graph) []taint.Finding

// scanDetector names an analyzer (matching its per-package binary and SARIF
// rule id) and its whole-program check.
type scanDetector struct {
	name  string
	check detectorCheck
}

// scanDetectors is the whole-program registry, ordered by name.
var scanDetectors = []scanDetector{
	{"cmdi", cmdi.Check},
	{"logi", logi.Check},
	{"ptrv", ptrv.Check},
	{"sqli", sqli.Check},
	{"ssrf", ssrf.Check},
	{"xss", xss.Check},
}

// scan exit codes follow govulncheck (and cmd/vuln): 0 clean, 3 findings, 1
// error, so CI can gate on the code.
const (
	scanExitClean    = 0
	scanExitError    = 1
	scanExitFindings = 3
)

const scanUsage = `usage: taint scan [flags] [packages]

Scan a whole program for taint vulnerabilities across package boundaries.
Unlike the per-package analyzers (the sqli, xss, ... binaries, which integrate
with go vet and golangci-lint), this builds one call graph over the whole
program, so a request handler in one package reaching a sink in another is
found.

Flags:
  -C dir            change to dir before scanning
  -analyzers list   comma-separated subset to run (default: all)
                    one or more of: cmdi, logi, ptrv, sqli, ssrf, xss
  -format format    output format: text, json, or sarif (default text)
  -tags list        comma-separated build tags
  -test             include test files and packages

Exit status is 0 when nothing is found, 3 when findings are reported, and 1 on
error.
`

// runScan is the headless whole-program scan behind "taint scan". It shares the
// interactive shell's engine but is a plain, scriptable command with text,
// JSON, and SARIF output, mirroring cmd/vuln.
func runScan(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("taint scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, scanUsage) }

	var (
		dir    string
		format string
		which  string
		tags   string
		tests  bool
	)
	fs.StringVar(&dir, "C", "", "change to `dir` before scanning")
	fs.StringVar(&format, "format", "text", "output `format`: text, json, or sarif")
	fs.StringVar(&which, "analyzers", "", "comma-separated subset of analyzers to run (default: all)")
	fs.StringVar(&tags, "tags", "", "comma-separated list of build tags")
	fs.BoolVar(&tests, "test", false, "include test files and packages")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return scanExitClean
		}
		fmt.Fprintln(stderr, "taint scan:", err)
		return scanExitError
	}
	switch format {
	case "text", "json", "sarif":
	default:
		fmt.Fprintf(stderr, "taint scan: unknown -format %q (want text, json, or sarif)\n", format)
		return scanExitError
	}
	selected, err := selectScanDetectors(which)
	if err != nil {
		fmt.Fprintln(stderr, "taint scan:", err)
		return scanExitError
	}

	fmt.Fprintln(stderr, "taint scan: loading packages...")
	prog, err := wholeprogram.Load(ctx, wholeprogram.Config{
		Dir:        dir,
		Patterns:   fs.Args(),
		Tests:      tests,
		BuildFlags: buildTagFlags(tags),
	})
	if err != nil {
		fmt.Fprintln(stderr, "taint scan:", err)
		return scanExitError
	}

	var findings []scanFinding
	for _, d := range selected {
		for _, f := range d.check(ctx, prog.CallGraph) {
			findings = append(findings, scanFinding{
				Analyzer: d.name,
				Position: prog.SSA.Fset.Position(f.Pos),
				Message:  f.Message,
			})
		}
	}
	if err := ctx.Err(); err != nil {
		// The scan was interrupted, so its findings are incomplete; a partial
		// list must not read as a clean result.
		fmt.Fprintln(stderr, "taint scan:", err)
		return scanExitError
	}
	sortScanFindings(findings)

	if err := writeScanReport(stdout, findings, format, scanRoot(dir)); err != nil {
		fmt.Fprintln(stderr, "taint scan:", err)
		return scanExitError
	}
	if len(findings) > 0 {
		return scanExitFindings
	}
	return scanExitClean
}

// selectScanDetectors resolves the -analyzers value to registry entries in
// registry order. An empty value selects all; an unknown name is an error.
func selectScanDetectors(which string) ([]scanDetector, error) {
	if strings.TrimSpace(which) == "" {
		return scanDetectors, nil
	}
	want := map[string]bool{}
	for _, name := range strings.Split(which, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !slices.ContainsFunc(scanDetectors, func(d scanDetector) bool { return d.name == name }) {
			return nil, fmt.Errorf("unknown analyzer %q (want cmdi, logi, ptrv, sqli, ssrf, or xss)", name)
		}
		want[name] = true
	}
	var out []scanDetector
	for _, d := range scanDetectors {
		if want[d.name] {
			out = append(out, d)
		}
	}
	return out, nil
}

// scanFinding is one located whole-program finding.
type scanFinding struct {
	Analyzer string
	Position token.Position
	Message  string
}

// sortScanFindings orders findings deterministically by file, line, column,
// analyzer, then message, so output is stable across runs.
func sortScanFindings(findings []scanFinding) {
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Position.Filename != b.Position.Filename {
			return a.Position.Filename < b.Position.Filename
		}
		if a.Position.Line != b.Position.Line {
			return a.Position.Line < b.Position.Line
		}
		if a.Position.Column != b.Position.Column {
			return a.Position.Column < b.Position.Column
		}
		if a.Analyzer != b.Analyzer {
			return a.Analyzer < b.Analyzer
		}
		return a.Message < b.Message
	})
}

// scanRoot resolves the directory findings are reported relative to: the
// absolute form of dir, or the working directory when dir is empty.
func scanRoot(dir string) string {
	if dir == "" {
		if wd, err := filepath.Abs("."); err == nil {
			return wd
		}
		return ""
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}

// relPath expresses path relative to root with forward slashes, falling back to
// the original path when it lies outside root.
func relPath(path, root string) string {
	if root == "" {
		return path
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

func writeScanReport(w io.Writer, findings []scanFinding, format, root string) error {
	switch format {
	case "json":
		return writeScanJSON(w, findings, root)
	case "sarif":
		return writeScanSARIF(w, findings, root)
	default:
		return writeScanText(w, findings, root)
	}
}

func writeScanText(w io.Writer, findings []scanFinding, root string) error {
	if len(findings) == 0 {
		_, err := fmt.Fprintln(w, "No taint issues found.")
		return err
	}
	for _, f := range findings {
		if _, err := fmt.Fprintf(w, "%s:%d:%d: %s (%s)\n",
			relPath(f.Position.Filename, root), f.Position.Line, f.Position.Column, f.Message, f.Analyzer); err != nil {
			return err
		}
	}
	return nil
}

// scanFindingJSON is the JSON shape of a finding: a stable, self-describing
// record rather than an imitation of another tool's format.
type scanFindingJSON struct {
	Analyzer string `json:"analyzer"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Message  string `json:"message"`
}

func writeScanJSON(w io.Writer, findings []scanFinding, root string) error {
	out := struct {
		Findings []scanFindingJSON `json:"findings"`
	}{Findings: make([]scanFindingJSON, 0, len(findings))}
	for _, f := range findings {
		out.Findings = append(out.Findings, scanFindingJSON{
			Analyzer: f.Analyzer,
			File:     relPath(f.Position.Filename, root),
			Line:     f.Position.Line,
			Column:   f.Position.Column,
			Message:  f.Message,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func writeScanSARIF(w io.Writer, findings []scanFinding, root string) error {
	sarifFindings := make([]analyzercmd.Finding, 0, len(findings))
	for _, f := range findings {
		sarifFindings = append(sarifFindings, analyzercmd.Finding{
			RuleID:  f.Analyzer,
			URI:     relPath(f.Position.Filename, root),
			Line:    f.Position.Line,
			Column:  f.Position.Column,
			Message: f.Message,
		})
	}
	log := analyzercmd.SARIFLogFromFindings("taint", "taint whole-program scan", sarifFindings)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// buildTagFlags turns a comma-separated tag list into go/packages build flags.
func buildTagFlags(tags string) []string {
	if strings.TrimSpace(tags) == "" {
		return nil
	}
	return []string{"-tags=" + tags}
}
