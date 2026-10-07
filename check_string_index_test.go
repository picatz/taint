package taint

import (
	"reflect"
	"testing"
)

const stringReconstructionHelpers = `
func source() string { return "user" }
func sink(string) {}
func clean(s string) string { return s }
func rebuild(s string) string {
	var out []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			out = append(out, '_')
			c += 'a' - 'A'
		}
		out = append(out, c)
	}
	return string(out)
}
func first[T ~string](s T) byte { return s[0] }
func inner() string { return source() }
func outer() string { return inner() }
func array() [2]string { return [2]string{"safe", source()} }
`

func stringReconstructionProgram(body string) string {
	return "package main\n" + stringReconstructionHelpers + "\nfunc main() {\n" + body + "\n}\n"
}

func TestCheckDetailedStringIndex(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{"direct", `sink(string(source()[0]))`, 1},
		{"append_byte", `var out []byte; out = append(out, source()[0]); sink(string(out))`, 1},
		{"reconstruct_loop", `s := source(); var out []byte; for i := 0; i < len(s); i++ { out = append(out, s[i]) }; sink(string(out))`, 1},
		{"reconstruct_helper", `sink(rebuild(source()))`, 1},
		{"named_string", `type text string; s := text(source()); sink(string(s[0]))`, 1},
		{"instantiated_generic_string", `sink(string(first(source())))`, 1},
		{"direct_round_trip", `sink(string([]byte(source())))`, 1},
		{"append_string", `var out []byte; out = append(out, source()...); sink(string(out))`, 1},
		{"clean_index", `sink(string("safe"[0]))`, 0},
		{"clean_reconstruction", `sink(rebuild("safe"))`, 0},
		{"unrelated_source", `_ = source(); sink(rebuild("safe"))`, 0},
		{"tainted_index_only", `i := int(source()[0]) % 4; sink(string("safe"[i]))`, 0},
		{"tainted_loop_bound_only", `n := int(source()[0]); var out []byte; for i := 0; i < n; i++ { out = append(out, 'x') }; sink(string(out))`, 0},
		{"discarded_reconstruction", `_ = rebuild(source()); sink(rebuild("safe"))`, 0},
		{"overwritten_result", `s := rebuild(source()); s = "safe"; sink(s)`, 0},
		{"sanitized_result", `sink(clean(rebuild(source())))`, 0},
		// String indexing must not introduce whole-array propagation: a
		// source in element 1 cannot taint a read of clean element 0.
		{"array_sibling", `sink(array()[0])`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cg, pkg := detailedGraphForSource(t, stringReconstructionProgram(tc.body))
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

func TestCheckDetailedStringIndexSummaryBound(t *testing.T) {
	cg, pkg := detailedGraphForSource(t, stringReconstructionProgram(`sink(string(outer()[0]))`))
	for _, tc := range []struct{ depth, want int }{{1, 0}, {2, 1}} {
		got := CheckDetailed(cg, NewSources(pkg+".source"), NewSinks(pkg+".sink"), WithMaxSummaryDepth(tc.depth))
		if len(got) != tc.want {
			t.Errorf("summary depth %d: got %d diagnostics, want %d", tc.depth, len(got), tc.want)
		}
	}
}

// The fixture loop is represented in SSA, never executed or unrolled. Each
// benchmark has exactly one sink path and excludes graph construction.
func BenchmarkCheckDetailedStringReconstruction(b *testing.B) {
	for _, tc := range []struct{ name, body string }{
		{"Direct", `sink(source())`},
		{"Index", `sink(string(source()[0]))`},
		{"Loop", `sink(rebuild(source()))`},
		{"CleanLoop", `sink(rebuild("safe"))`},
	} {
		b.Run(tc.name, func(b *testing.B) {
			cg, pkg := buildBenchCallGraph(b, stringReconstructionProgram(tc.body))
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
