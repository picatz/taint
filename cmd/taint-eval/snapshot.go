package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Finding is a single analyzer diagnostic recorded in a snapshot.
// Paths are stored relative to the target repo root so snapshots are
// machine-independent.
type Finding struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Message string `json:"message"`
}

// AnalyzerResult records the findings for a single analyzer on a target.
type AnalyzerResult struct {
	Count    int       `json:"count"`
	Findings []Finding `json:"findings"`
}

// Snapshot is the on-disk representation of expected analyzer output for a
// single target.
type Snapshot struct {
	Target    string                    `json:"target"`
	Kind      TargetKind                `json:"kind"`
	Source    string                    `json:"source,omitempty"`
	Commit    string                    `json:"commit,omitempty"`
	Analyzers map[string]AnalyzerResult `json:"analyzers"`
}

// SnapshotPath returns the conventional snapshot location for a target.
func SnapshotPath(snapshotsDir, targetName string) string {
	return filepath.Join(snapshotsDir, targetName+".json")
}

// LoadSnapshot reads a snapshot file. A non-existent file is reported as
// (nil, os.ErrNotExist) so callers can distinguish "no baseline" from "read
// error".
func LoadSnapshot(path string) (*Snapshot, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("parse snapshot %s: %w", path, err)
	}
	s.normalize()
	return &s, nil
}

// WriteSnapshot writes a snapshot atomically with deterministic ordering.
func WriteSnapshot(path string, s *Snapshot) error {
	s.normalize()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// normalize sorts findings deterministically so identical analyzer output
// always produces the same snapshot bytes.
func (s *Snapshot) normalize() {
	if s.Analyzers == nil {
		s.Analyzers = map[string]AnalyzerResult{}
		return
	}
	for name, res := range s.Analyzers {
		if res.Findings == nil {
			res.Findings = []Finding{}
		}
		sort.SliceStable(res.Findings, func(i, j int) bool {
			a, b := res.Findings[i], res.Findings[j]
			if a.File != b.File {
				return a.File < b.File
			}
			if a.Line != b.Line {
				return a.Line < b.Line
			}
			if a.Column != b.Column {
				return a.Column < b.Column
			}
			return a.Message < b.Message
		})
		res.Count = len(res.Findings)
		s.Analyzers[name] = res
	}
}

// Diff describes the drift between an expected snapshot and an actual run.
type Diff struct {
	Target    string
	Analyzer  string
	Missing   []Finding // expected but absent
	Unexpected []Finding // present but not expected
}

// HasDrift reports whether the diff records any unexpected change.
func (d Diff) HasDrift() bool {
	return len(d.Missing) > 0 || len(d.Unexpected) > 0
}

// DiffSnapshots compares an expected snapshot against the analyzer output of
// a single run. Analyzers present in either snapshot are compared; analyzers
// absent from both are skipped.
func DiffSnapshots(target string, expected, actual *Snapshot) []Diff {
	analyzers := map[string]struct{}{}
	if expected != nil {
		for name := range expected.Analyzers {
			analyzers[name] = struct{}{}
		}
	}
	if actual != nil {
		for name := range actual.Analyzers {
			analyzers[name] = struct{}{}
		}
	}
	names := make([]string, 0, len(analyzers))
	for name := range analyzers {
		names = append(names, name)
	}
	sort.Strings(names)

	var diffs []Diff
	for _, name := range names {
		exp := AnalyzerResult{}
		act := AnalyzerResult{}
		if expected != nil {
			exp = expected.Analyzers[name]
		}
		if actual != nil {
			act = actual.Analyzers[name]
		}
		d := Diff{Target: target, Analyzer: name}
		expSet := indexFindings(exp.Findings)
		actSet := indexFindings(act.Findings)
		for key, f := range expSet {
			if _, ok := actSet[key]; !ok {
				d.Missing = append(d.Missing, f)
			}
		}
		for key, f := range actSet {
			if _, ok := expSet[key]; !ok {
				d.Unexpected = append(d.Unexpected, f)
			}
		}
		sortFindings(d.Missing)
		sortFindings(d.Unexpected)
		if d.HasDrift() {
			diffs = append(diffs, d)
		}
	}
	return diffs
}

func indexFindings(fs []Finding) map[string]Finding {
	out := make(map[string]Finding, len(fs))
	for _, f := range fs {
		out[findingKey(f)] = f
	}
	return out
}

func findingKey(f Finding) string {
	return fmt.Sprintf("%s:%d:%d|%s", f.File, f.Line, f.Column, f.Message)
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		return a.Message < b.Message
	})
}

// FormatDiffs renders diffs to a human-readable string for terminal output.
func FormatDiffs(diffs []Diff) string {
	if len(diffs) == 0 {
		return ""
	}
	var b strings.Builder
	for _, d := range diffs {
		fmt.Fprintf(&b, "drift in target=%s analyzer=%s\n", d.Target, d.Analyzer)
		for _, f := range d.Missing {
			fmt.Fprintf(&b, "  - expected but missing: %s:%d:%d %s\n", f.File, f.Line, f.Column, f.Message)
		}
		for _, f := range d.Unexpected {
			fmt.Fprintf(&b, "  + unexpected finding:   %s:%d:%d %s\n", f.File, f.Line, f.Column, f.Message)
		}
	}
	return b.String()
}
