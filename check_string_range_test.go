package taint

import (
	"reflect"
	"testing"

	"golang.org/x/tools/go/ssa"
)

const stringRangeHelpers = `
func source() string { return "user' OR '1'='1" }
func sink(string) {}
func clean(s string) string { return s }
func rebuildRunes(s string) string {
	var out []rune
	for _, r := range s {
		out = append(out, r)
	}
	return string(out)
}
func inner() string { return source() }
func outer() string { return inner() }
`

func stringRangeProgram(body string) string {
	return "package main\n" + stringRangeHelpers + "\nfunc main() {\n" + body + "\n}\n"
}

func TestCheckDetailedStringRange(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{"rune_to_string", `for _, r := range source() { sink(string(r)) }`, 1},
		{"rune_slice", `var out []rune; for _, r := range source() { out = append(out, r) }; sink(string(out))`, 1},
		{"concatenation", `var out string; for _, r := range source() { out += string(r) }; sink(out)`, 1},
		{"helper", `sink(rebuildRunes(source()))`, 1},
		{"named_string", `type text string; s := text(source()); for _, r := range s { sink(string(r)) }`, 1},
		{"transformed_rune", `var out []rune; for _, r := range source() { if r >= 'A' && r <= 'Z' { r += 'a' - 'A' }; out = append(out, r) }; sink(string(out))`, 1},
		{"clean_unicode", `sink(rebuildRunes("safe 日本語"))`, 0},
		{"unrelated_source", `_ = source(); sink(rebuildRunes("safe"))`, 0},
		{"offset_only", `var out []rune; for i := range source() { out = append(out, rune(i)) }; sink(string(out))`, 0},
		{"constant_output", `var out []rune; for range source() { out = append(out, 'x') }; sink(string(out))`, 0},
		{"map_with_tainted_key", `var out []rune; for _, r := range map[int]rune{int(source()[0]): 'x'} { out = append(out, r) }; sink(string(out))`, 0},
		{"discarded_result", `_ = rebuildRunes(source()); sink(rebuildRunes("safe"))`, 0},
		{"overwritten_result", `s := rebuildRunes(source()); s = "safe"; sink(s)`, 0},
		{"sanitized_result", `sink(clean(rebuildRunes(source())))`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cg, pkg := detailedGraphForSource(t, stringRangeProgram(tc.body))
			sources, sinks := NewSources(pkg+".source"), NewSinks(pkg+".sink")
			opts := []Option{WithSanitizers(pkg + ".clean")}
			got := CheckDetailed(cg, sources, sinks, opts...)
			if len(got) != tc.want {
				t.Fatalf("got %d diagnostics, want %d", len(got), tc.want)
			}
			if !reflect.DeepEqual(got, CheckDetailed(cg, sources, sinks, opts...)) {
				t.Fatal("repeated check changed diagnostic or evidence ordering")
			}
			if tc.want == 0 {
				return
			}
			d := got[0]
			if d.Result.SourceType != pkg+".source" || d.Result.SourceValue == nil || d.Result.SourceValue.String() != pkg+".source" {
				t.Fatalf("wrong source attribution: %+v", d.Result)
			}
			if d.Result.SinkType != pkg+".sink" || !d.Result.ReportPos().IsValid() {
				t.Fatalf("wrong sink attribution: %+v", d.Result)
			}
			assertEvidenceOrder(t, evidenceKinds(d.Evidence), EvidenceSourceMatch, EvidenceSinkMatch)
			assertEvidenceRule(t, d.Evidence, EvidenceSourceMatch, pkg+".source")
			assertEvidenceRule(t, d.Evidence, EvidenceSinkMatch, pkg+".sink")
			assertEvidenceContains(t, evidenceKinds(d.Evidence), EvidencePropagationStep)
		})
	}
}

func TestStringRangeTupleComponents(t *testing.T) {
	cg, pkg := detailedGraphForSource(t, stringRangeProgram(`for i, r := range source() { sink(string(r) + string(rune(i))) }`))
	ctx := newTaintContext(NewSources(pkg+".source"), defaultMaxSummaryDepth)
	seen := map[int]bool{}
	for _, node := range cg.Nodes {
		if node.Func == nil || node.Func.Name() != "main" {
			continue
		}
		for _, block := range node.Func.Blocks {
			for _, instr := range block.Instrs {
				extract, ok := instr.(*ssa.Extract)
				if !ok {
					continue
				}
				next, ok := extract.Tuple.(*ssa.Next)
				if !ok || !next.IsString {
					continue
				}
				seen[extract.Index] = true
				tainted, _, _ := checkSSAValueWithContext(nil, ctx, extract, valueSet{})
				if tainted != (extract.Index == 2) {
					t.Errorf("string iterator component %d: tainted=%v; only the rune component should propagate content", extract.Index, tainted)
				}
			}
		}
	}
	if len(seen) != 3 {
		t.Fatalf("expected ok, offset and rune extracts, got %v", seen)
	}
}

func TestCheckDetailedStringRangeSummaryBound(t *testing.T) {
	cg, pkg := detailedGraphForSource(t, stringRangeProgram(`for _, r := range outer() { sink(string(r)) }`))
	for _, tc := range []struct{ depth, want int }{{1, 0}, {2, 1}} {
		got := CheckDetailed(cg, NewSources(pkg+".source"), NewSinks(pkg+".sink"), WithMaxSummaryDepth(tc.depth))
		if len(got) != tc.want {
			t.Errorf("summary depth %d: got %d diagnostics, want %d", tc.depth, len(got), tc.want)
		}
	}
}

// The source loop is analyzed as SSA and never executed or unrolled. Every
// fixture has one sink path; graph construction is outside the timed loop.
func BenchmarkCheckDetailedStringRange(b *testing.B) {
	for _, tc := range []struct{ name, body string }{
		{"Direct", `sink(source())`},
		{"Rune", `for _, r := range source() { sink(string(r)) }`},
		{"Loop", `sink(rebuildRunes(source()))`},
		{"CleanLoop", `sink(rebuildRunes("safe"))`},
	} {
		b.Run(tc.name, func(b *testing.B) {
			cg, pkg := buildBenchCallGraph(b, stringRangeProgram(tc.body))
			sources, sinks := NewSources(pkg+".source"), NewSinks(pkg+".sink")
			paths := countSinkPaths(cg, sources, sinks)
			b.ReportAllocs()
			for b.Loop() {
				benchDiagnosticsSink = CheckDetailed(cg, sources, sinks)
			}
			b.ReportMetric(float64(paths), "paths")
			b.ReportMetric(float64(len(benchDiagnosticsSink)), "findings")
		})
	}
}
