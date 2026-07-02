package main

import (
	"strings"
	"testing"
)

func scoreTargetFixture() (Target, *Snapshot) {
	t := Target{
		Name:      "demo",
		Kind:      KindLocal,
		Path:      "./demo",
		Analyzers: []string{"cmdi", "sqli", "xss"},
		Expect: []ExpectedFinding{
			{Analyzer: "sqli", File: "db.go", Line: 10, Note: "CVE-0000-0001"},
			{Analyzer: "cmdi", File: "run.go", Note: "any-line entry"},
			{Analyzer: "xss", File: "web.go", Line: 5},
		},
	}
	snap := &Snapshot{
		Target: "demo",
		Kind:   KindLocal,
		Analyzers: map[string]AnalyzerResult{
			// Matches the sqli expectation exactly.
			"sqli": {Findings: []Finding{{File: "db.go", Line: 10, Column: 3, Message: "potential sql injection"}}},
			// Matches the any-line cmdi expectation, plus one unexpected
			// finding in another file.
			"cmdi": {Findings: []Finding{
				{File: "run.go", Line: 99, Column: 1, Message: "potential command injection"},
				{File: "other.go", Line: 4, Column: 2, Message: "potential command injection"},
			}},
			// No xss findings: the xss expectation is missed.
			"xss": {},
		},
	}
	snap.normalize()
	return t, snap
}

func TestScoreTarget(t *testing.T) {
	target, snap := scoreTargetFixture()
	rep := ScoreTarget(target, snap)

	if got := len(rep.Matched); got != 2 {
		t.Fatalf("matched = %d, want 2 (%+v)", got, rep.Matched)
	}
	if got := len(rep.Missed); got != 1 || rep.Missed[0].Analyzer != "xss" {
		t.Fatalf("missed = %+v, want the xss expectation", rep.Missed)
	}
	if got := rep.Unexpected["cmdi"]; len(got) != 1 || got[0].File != "other.go" {
		t.Fatalf("unexpected cmdi = %+v, want other.go only", got)
	}
	if got := rep.Unexpected["sqli"]; len(got) != 0 {
		t.Fatalf("unexpected sqli = %+v, want none", got)
	}
}

func TestScoreTarget_NilSnapshotMissesEverything(t *testing.T) {
	target, _ := scoreTargetFixture()
	rep := ScoreTarget(target, nil)
	if len(rep.Matched) != 0 || len(rep.Missed) != len(target.Expect) {
		t.Fatalf("nil snapshot: matched=%d missed=%d, want 0/%d", len(rep.Matched), len(rep.Missed), len(target.Expect))
	}
}

func TestScoreTarget_LineZeroMatchesAnyLine(t *testing.T) {
	e := ExpectedFinding{Analyzer: "sqli", File: "db.go"}
	if !e.Matches("sqli", Finding{File: "db.go", Line: 123}) {
		t.Fatal("line 0 should match any line")
	}
	if e.Matches("sqli", Finding{File: "other.go", Line: 123}) {
		t.Fatal("different file must not match")
	}
	if e.Matches("cmdi", Finding{File: "db.go", Line: 123}) {
		t.Fatal("different analyzer must not match")
	}
	pinned := ExpectedFinding{Analyzer: "sqli", File: "db.go", Line: 10}
	if pinned.Matches("sqli", Finding{File: "db.go", Line: 11}) {
		t.Fatal("pinned line must not match a different line")
	}
}

func TestAggregateScoresAndTable(t *testing.T) {
	target, snap := scoreTargetFixture()
	rep := ScoreTarget(target, snap)
	scores := AggregateScores([]Target{target}, []TargetReport{rep})

	if s := scores["sqli"]; s != (Score{TP: 1}) {
		t.Fatalf("sqli score = %+v", s)
	}
	if s := scores["cmdi"]; s != (Score{TP: 1, FP: 1}) {
		t.Fatalf("cmdi score = %+v", s)
	}
	if s := scores["xss"]; s != (Score{FN: 1}) {
		t.Fatalf("xss score = %+v", s)
	}

	if p, ok := scores["cmdi"].Precision(); !ok || p != 0.5 {
		t.Fatalf("cmdi precision = %v/%v, want 0.5", p, ok)
	}
	if r, ok := scores["xss"].Recall(); !ok || r != 0 {
		t.Fatalf("xss recall = %v/%v, want 0", r, ok)
	}
	if _, ok := (Score{}).Precision(); ok {
		t.Fatal("precision should be undefined with no positives")
	}
	if _, ok := (Score{}).Recall(); ok {
		t.Fatal("recall should be undefined with no expectations")
	}

	table := FormatScoreTable(scores)
	for _, want := range []string{"ANALYZER", "cmdi", "0.50", "TOTAL"} {
		if !strings.Contains(table, want) {
			t.Fatalf("table missing %q:\n%s", want, table)
		}
	}
}

func TestFormatTargetReport(t *testing.T) {
	target, snap := scoreTargetFixture()
	rep := ScoreTarget(target, snap)
	out := FormatTargetReport(rep)
	for _, want := range []string{
		"demo: 2 matched, 1 missed, 1 unexpected",
		"= matched  sqli db.go:10 at db.go:10:3 (CVE-0000-0001)",
		"- missed   xss web.go:5",
		"+ unexpected cmdi other.go:4:2 potential command injection",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("report missing %q:\n%s", want, out)
		}
	}

	clean := ScoreTarget(Target{Name: "clean", Analyzers: []string{"sqli"}}, &Snapshot{Analyzers: map[string]AnalyzerResult{"sqli": {}}})
	if got := FormatTargetReport(clean); got != "clean: OK\n" {
		t.Fatalf("clean report = %q", got)
	}
}
