package main

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
)

// ExpectMatch pairs a satisfied expectation with the actual findings that
// satisfied it.
type ExpectMatch struct {
	Expect   ExpectedFinding
	Findings []Finding
}

// TargetReport is the ground-truth outcome for a single target run.
//
// Every actual finding is either "explained" by an expectation (it matches
// one of the target's expect entries) or unexpected. Every expectation is
// either matched by at least one actual finding or missed.
type TargetReport struct {
	Target string
	// Matched expectations (true positives).
	Matched []ExpectMatch
	// Missed expectations (false negatives).
	Missed []ExpectedFinding
	// Unexpected findings per analyzer (false positives against ground
	// truth — though on a not-yet-triaged target they may also be
	// undocumented true positives worth reviewing).
	Unexpected map[string][]Finding
}

// Score is the aggregate confusion count for one analyzer.
type Score struct {
	TP int // matched expectations
	FN int // missed expectations
	FP int // unexpected findings
}

// Precision returns TP/(TP+FP) and false when undefined (no positives at
// all, so there is nothing to be precise about).
func (s Score) Precision() (float64, bool) {
	if s.TP+s.FP == 0 {
		return 0, false
	}
	return float64(s.TP) / float64(s.TP+s.FP), true
}

// Recall returns TP/(TP+FN) and false when undefined (no ground-truth
// expectations for this analyzer).
func (s Score) Recall() (float64, bool) {
	if s.TP+s.FN == 0 {
		return 0, false
	}
	return float64(s.TP) / float64(s.TP+s.FN), true
}

// ScoreTarget compares a fresh run against the target's ground-truth expect
// entries. A snapshot is not involved: this is expectation vs reality, not
// drift vs baseline.
func ScoreTarget(t Target, actual *Snapshot) TargetReport {
	rep := TargetReport{Target: t.Name, Unexpected: map[string][]Finding{}}
	if actual == nil {
		rep.Missed = append(rep.Missed, t.Expect...)
		return rep
	}
	for _, e := range t.Expect {
		var hits []Finding
		if res, ok := actual.Analyzers[e.Analyzer]; ok {
			for _, f := range res.Findings {
				if e.Matches(e.Analyzer, f) {
					hits = append(hits, f)
				}
			}
		}
		if len(hits) > 0 {
			rep.Matched = append(rep.Matched, ExpectMatch{Expect: e, Findings: hits})
		} else {
			rep.Missed = append(rep.Missed, e)
		}
	}
	for name, res := range actual.Analyzers {
		for _, f := range res.Findings {
			explained := false
			for _, e := range t.Expect {
				if e.Matches(name, f) {
					explained = true
					break
				}
			}
			if !explained {
				rep.Unexpected[name] = append(rep.Unexpected[name], f)
			}
		}
	}
	for name := range rep.Unexpected {
		sortFindings(rep.Unexpected[name])
	}
	return rep
}

// AggregateScores folds per-target reports into per-analyzer confusion
// counts. The analyzer set is taken from the targets' configuration so
// analyzers that produced no findings still get a row.
func AggregateScores(targets []Target, reports []TargetReport) map[string]Score {
	scores := map[string]Score{}
	for _, t := range targets {
		for _, name := range t.Analyzers {
			if _, ok := scores[name]; !ok {
				scores[name] = Score{}
			}
		}
	}
	for _, rep := range reports {
		for _, m := range rep.Matched {
			s := scores[m.Expect.Analyzer]
			s.TP++
			scores[m.Expect.Analyzer] = s
		}
		for _, e := range rep.Missed {
			s := scores[e.Analyzer]
			s.FN++
			scores[e.Analyzer] = s
		}
		for name, fs := range rep.Unexpected {
			s := scores[name]
			s.FP += len(fs)
			scores[name] = s
		}
	}
	return scores
}

// FormatTargetReport renders one target's ground-truth outcome. The header
// line always prints; detail lines only appear when there is something to
// say.
func FormatTargetReport(rep TargetReport) string {
	var b strings.Builder
	status := "OK"
	if len(rep.Missed) > 0 || totalUnexpected(rep) > 0 {
		parts := []string{}
		if len(rep.Matched) > 0 {
			parts = append(parts, fmt.Sprintf("%d matched", len(rep.Matched)))
		}
		if len(rep.Missed) > 0 {
			parts = append(parts, fmt.Sprintf("%d missed", len(rep.Missed)))
		}
		if n := totalUnexpected(rep); n > 0 {
			parts = append(parts, fmt.Sprintf("%d unexpected", n))
		}
		status = strings.Join(parts, ", ")
	} else if len(rep.Matched) > 0 {
		status = fmt.Sprintf("OK (%d/%d expected findings)", len(rep.Matched), len(rep.Matched))
	}
	fmt.Fprintf(&b, "%s: %s\n", rep.Target, status)
	for _, m := range rep.Matched {
		fmt.Fprintf(&b, "  = matched  %s %s%s%s\n", m.Expect.Analyzer, expectPos(m.Expect), findingPositions(m.Findings), noteSuffix(m.Expect))
	}
	for _, e := range rep.Missed {
		fmt.Fprintf(&b, "  - missed   %s %s%s\n", e.Analyzer, expectPos(e), noteSuffix(e))
	}
	names := make([]string, 0, len(rep.Unexpected))
	for name := range rep.Unexpected {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, f := range rep.Unexpected[name] {
			fmt.Fprintf(&b, "  + unexpected %s %s:%d:%d %s\n", name, f.File, f.Line, f.Column, f.Message)
		}
	}
	return b.String()
}

func totalUnexpected(rep TargetReport) int {
	n := 0
	for _, fs := range rep.Unexpected {
		n += len(fs)
	}
	return n
}

func expectPos(e ExpectedFinding) string {
	if e.Line == 0 {
		return e.File
	}
	return fmt.Sprintf("%s:%d", e.File, e.Line)
}

func noteSuffix(e ExpectedFinding) string {
	if e.Note == "" {
		return ""
	}
	return " (" + e.Note + ")"
}

func findingPositions(fs []Finding) string {
	if len(fs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(fs))
	for _, f := range fs {
		parts = append(parts, fmt.Sprintf("%s:%d:%d", f.File, f.Line, f.Column))
	}
	return " at " + strings.Join(parts, ", ")
}

// FormatScoreTable renders the per-analyzer precision/recall table.
// "n/a" means the denominator is zero: no positives for precision, no
// ground-truth expectations for recall.
func FormatScoreTable(scores map[string]Score) string {
	names := make([]string, 0, len(scores))
	for name := range scores {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ANALYZER\tTP\tFN\tFP\tPRECISION\tRECALL")
	var total Score
	for _, name := range names {
		s := scores[name]
		total.TP += s.TP
		total.FN += s.FN
		total.FP += s.FP
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%s\t%s\n", name, s.TP, s.FN, s.FP, formatRatio(s.Precision()), formatRatio(s.Recall()))
	}
	fmt.Fprintf(tw, "TOTAL\t%d\t%d\t%d\t%s\t%s\n", total.TP, total.FN, total.FP, formatRatio(total.Precision()), formatRatio(total.Recall()))
	_ = tw.Flush()
	return b.String()
}

func formatRatio(v float64, ok bool) string {
	if !ok {
		return "n/a"
	}
	return fmt.Sprintf("%.2f", v)
}

// runReport executes the analyzers and scores the output against the
// manifest's ground-truth expect entries. Unlike check, report never fails
// on the numbers themselves: the scoreboard records reality (misses on real
// CVE targets are expected data points, not harness errors). Only
// infrastructure problems (clone, build, load failures) produce a non-zero
// exit.
func runReport(ctx context.Context, stdout, stderr io.Writer, repoRoot, cacheOverride, manifestDir, snapshotsDir, sarifDir string, targets []Target, jobs int) error {
	cacheDir, cmdFor, err := prepareRun(ctx, repoRoot, cacheOverride, targets)
	if err != nil {
		return err
	}
	runs := runTargets(ctx, targets, jobs, func(c context.Context, t Target) (*Snapshot, error) {
		root, err := resolveTargetRoot(c, t, cacheDir, manifestDir)
		if err != nil {
			return nil, err
		}
		return RunTarget(c, t, root, cmdFor)
	})
	var firstErr error
	reports := make([]TargetReport, 0, len(runs))
	scored := make([]Target, 0, len(runs))
	for _, r := range runs {
		if r.err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("target %q: %w", r.target.Name, r.err)
			}
			fmt.Fprintf(stdout, "%s: ERROR %v\n", r.target.Name, r.err)
			continue
		}
		if sarifDir != "" {
			if err := WriteSnapshotSARIF(sarifDir, r.target.Name, r.snap); err != nil {
				return err
			}
		}
		rep := ScoreTarget(r.target, r.snap)
		reports = append(reports, rep)
		scored = append(scored, r.target)
		fmt.Fprint(stdout, FormatTargetReport(rep))
	}
	fmt.Fprintln(stdout)
	fmt.Fprint(stdout, FormatScoreTable(AggregateScores(scored, reports)))
	return firstErr
}
