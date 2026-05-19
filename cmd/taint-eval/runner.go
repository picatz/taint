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
	doc, parseErr := parseAnalyzerJSON(stdout.Bytes())
	if parseErr != nil {
		return nil, stderr.Bytes(), fmt.Errorf("%s: parse json: %w (stderr: %s)", filepath.Base(bin), parseErr, stderr.String())
	}
	return doc, stderr.Bytes(), nil
}

// parseAnalyzerJSON tolerates the small amount of plain-text warning output
// that singlechecker writes before its JSON document.
func parseAnalyzerJSON(out []byte) (AnalyzerJSON, error) {
	// singlechecker writes a single JSON object. Trim any leading whitespace
	// or text that precedes the first '{' (some analyzers print harmless
	// flag-conflict warnings before the JSON body).
	idx := bytes.IndexByte(out, '{')
	if idx < 0 {
		return AnalyzerJSON{}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(out[idx:]))
	dec.DisallowUnknownFields()
	var doc AnalyzerJSON
	if err := dec.Decode(&doc); err != nil && err != io.EOF {
		return nil, err
	}
	return doc, nil
}

// RunTarget invokes every analyzer configured on a target and returns a
// freshly-computed Snapshot.
func RunTarget(ctx context.Context, t Target, root string, cmdFor analyzerCommand) (*Snapshot, error) {
	snap := &Snapshot{
		Target:    t.Name,
		Kind:      t.Kind,
		Source:    targetSource(t),
		Commit:    t.Commit,
		Analyzers: map[string]AnalyzerResult{},
	}
	for _, name := range t.Analyzers {
		bin, err := cmdFor(name)
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

func targetSource(t Target) string {
	switch t.Kind {
	case KindGit:
		return t.Repo
	case KindLocal:
		return t.Path
	}
	return ""
}
