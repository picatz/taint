package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// analyzerCommand resolves an analyzer name to a built binary path.
// Implementations are tested through a function rather than a fixed list so
// runner tests can swap in fakes without spawning child processes.
type analyzerCommand func(name string) (string, error)

// runAnalyzer executes one analyzer binary against the target directory and
// returns its parsed JSON output. Stderr from the analyzer is appended to
// outBuf for surfacing on failure but never causes the command to fail on
// its own — analyzers emit informational stderr (e.g. "flag -debug would
// conflict") even on clean runs.
func runAnalyzer(ctx context.Context, bin, dir string, pkgs []string, env []string) (AnalyzerJSON, []byte, error) {
	args := append([]string{"-json"}, pkgs...)
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	if env != nil {
		cmd.Env = env
	} else {
		cmd.Env = os.Environ()
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		// singlechecker exits non-zero only when packages fail to load.
		// With -json, diagnostics never trigger a non-zero exit.
		if stdout.Len() == 0 {
			return nil, stderr.Bytes(), fmt.Errorf("%s: %w (stderr: %s)", filepath.Base(bin), err, stderr.String())
		}
	}
	doc, warnings, parseErr := parseAnalyzerJSON(stdout.Bytes())
	if parseErr != nil {
		return nil, stderr.Bytes(), fmt.Errorf("%s: parse json: %w (stderr: %s)", filepath.Base(bin), parseErr, stderr.String())
	}
	for _, w := range warnings {
		fmt.Fprintf(&stderr, "%s: warning: %s\n", filepath.Base(bin), w)
	}
	return doc, stderr.Bytes(), nil
}

// parseAnalyzerJSON tolerates the small amount of plain-text warning output
// that singlechecker writes before its JSON document, as well as per-package
// error entries inside it.
//
// The document is singlechecker's JSONTree: package ID → analyzer name →
// either a diagnostic array or an {"error": "..."} object for packages that
// failed to load. Test-augmented variants of real-world pinned targets
// sometimes fail to typecheck even though the plain package is fine (e.g. a
// stale _test.go in a vulnerable release); the plain package's diagnostics
// are what the harness cares about, so error entries are returned as
// warnings instead of failing the run.
func parseAnalyzerJSON(out []byte) (AnalyzerJSON, []string, error) {
	// singlechecker writes a single JSON object. Trim any leading whitespace
	// or text that precedes the first '{' (some analyzers print harmless
	// flag-conflict warnings before the JSON body).
	idx := bytes.IndexByte(out, '{')
	if idx < 0 {
		return AnalyzerJSON{}, nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(out[idx:]))
	var raw map[string]map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil && err != io.EOF {
		return nil, nil, err
	}
	doc := AnalyzerJSON{}
	var warnings []string
	for pkg, byAnalyzer := range raw {
		for name, msg := range byAnalyzer {
			var diags []AnalyzerDiagnosticJSON
			if err := json.Unmarshal(msg, &diags); err == nil {
				if doc[pkg] == nil {
					doc[pkg] = map[string][]AnalyzerDiagnosticJSON{}
				}
				doc[pkg][name] = diags
				continue
			}
			var e struct {
				Err string `json:"error"`
			}
			if err := json.Unmarshal(msg, &e); err != nil || e.Err == "" {
				return nil, nil, fmt.Errorf("package %s analyzer %s: unrecognized entry %s", pkg, name, msg)
			}
			warnings = append(warnings, fmt.Sprintf("package %s (%s): %s", pkg, name, e.Err))
		}
	}
	sort.Strings(warnings)
	return doc, warnings, nil
}

// RunTarget invokes every analyzer configured on a target and returns a
// freshly-computed Snapshot.
func RunTarget(ctx context.Context, t Target, root string, bins binaries) (*Snapshot, error) {
	snap := &Snapshot{
		Target:    t.Name,
		Kind:      t.Kind,
		Source:    targetSource(t),
		Commit:    t.Commit,
		Analyzers: map[string]AnalyzerResult{},
	}
	if t.WholeProgram {
		if err := runWholeProgramTarget(ctx, t, root, bins.taint, snap); err != nil {
			return nil, err
		}
		snap.normalize()
		return snap, nil
	}
	for _, name := range t.Analyzers {
		bin, err := bins.analyzer(name)
		if err != nil {
			return nil, err
		}
		doc, _, err := runAnalyzer(ctx, bin, root, t.Packages, nil)
		if err != nil {
			return nil, fmt.Errorf("target %q analyzer %q: %w", t.Name, name, err)
		}
		merged := MergeAnalyzerJSON(doc)
		// singlechecker keys diagnostics by the analyzer's own name. We
		// trust the configured analyzer name here because the binary itself
		// is the single source of truth for which analyzer ran.
		var diags []AnalyzerDiagnosticJSON
		for _, d := range merged {
			diags = append(diags, d...)
		}
		out := Normalize(map[string][]AnalyzerDiagnosticJSON{name: diags}, root)
		snap.Analyzers[name] = out[name]
	}
	snap.normalize()
	return snap, nil
}

// runWholeProgramTarget runs "taint scan" once over the target with its
// configured analyzers and buckets the findings into the snapshot by analyzer.
// A single scan loads the whole program once, and the subprocess reclaims its
// memory on exit, so a heavy program does not accumulate in the harness.
func runWholeProgramTarget(ctx context.Context, t Target, root, taintBin string, snap *Snapshot) error {
	// Seed every configured analyzer so one with no findings still records a
	// zero result, matching the per-package path.
	for _, name := range t.Analyzers {
		snap.Analyzers[name] = AnalyzerResult{}
	}
	findings, err := runTaintScan(ctx, taintBin, t.Analyzers, root, t.Packages)
	if err != nil {
		return fmt.Errorf("target %q whole-program scan: %w", t.Name, err)
	}
	seen := map[string]map[string]struct{}{}
	for _, f := range findings {
		res, ok := snap.Analyzers[f.Analyzer]
		if !ok {
			// A finding for an analyzer the target did not request should not
			// happen (scan is told exactly which to run), but ignore it rather
			// than record an unconfigured analyzer.
			continue
		}
		if seen[f.Analyzer] == nil {
			seen[f.Analyzer] = map[string]struct{}{}
		}
		finding := Finding{File: f.File, Line: f.Line, Column: f.Column, Message: f.Message}
		key := findingKey(finding)
		if _, dup := seen[f.Analyzer][key]; dup {
			continue
		}
		seen[f.Analyzer][key] = struct{}{}
		res.Findings = append(res.Findings, finding)
		res.Count = len(res.Findings)
		snap.Analyzers[f.Analyzer] = res
	}
	return nil
}

// scanFinding is one finding from "taint scan -format json". Paths are already
// relative to the scan root, so they map straight onto a snapshot Finding.
type scanFinding struct {
	Analyzer string `json:"analyzer"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Message  string `json:"message"`
}

// runTaintScan invokes "taint scan" over root with the given analyzers and
// returns its findings. Running in root (cmd.Dir) means scan reports paths
// relative to it, which is the snapshot's path convention.
func runTaintScan(ctx context.Context, taintBin string, analyzers []string, root string, pkgs []string) ([]scanFinding, error) {
	if taintBin == "" {
		return nil, fmt.Errorf("taint binary not built")
	}
	args := []string{"scan", "-analyzers", strings.Join(analyzers, ","), "-format", "json"}
	args = append(args, pkgs...)
	cmd := exec.CommandContext(ctx, taintBin, args...)
	cmd.Dir = root
	cmd.Env = os.Environ()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	// scan exits 3 when it reports findings; that is success, not failure.
	if err != nil {
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 3 {
			return nil, fmt.Errorf("%w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
		}
	}
	var doc struct {
		Findings []scanFinding `json:"findings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		return nil, fmt.Errorf("parse scan json: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	return doc.Findings, nil
}

func targetSource(t Target) string {
	switch t.Kind {
	case KindGit:
		return t.Repo
	case KindLocal:
		return t.Path
	}
	return ""
}
