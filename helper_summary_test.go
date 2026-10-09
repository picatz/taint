package taint

import (
	"fmt"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"reflect"
	"strings"
	"testing"
)

func helperSummaryProgram(shape string, n int) string {
	var body strings.Builder
	body.WriteString("m[\"q\"] = value\n")
	for i := 0; i < n; i++ {
		switch shape {
		case "Diamonds":
			fmt.Fprintf(&body, "if flag() { noise(%d) } else { noise(%d) }\n", i, -i-1)
		case "Loops":
			fmt.Fprintf(&body, "for flag() { noise(%d) }\n", i)
		}
	}
	return "package main\nfunc source() string { return \"user\" }; func sink(string) {}; func flag() bool { return true }; func noise(int) {}\nfunc helper(m map[string]string, value string) {\n" + body.String() + "}\nfunc main(){ m:=make(map[string]string); helper(m,source()); sink(m[\"q\"]) }\n"
}

func helperSummaryQueries(cg *callgraph.Graph) (*ssa.Function, *ssa.Call, *ssa.Lookup) {
	var helper *ssa.Function
	var call *ssa.Call
	var lookup *ssa.Lookup
	for fn := range cg.Nodes {
		if fn == nil {
			continue
		}
		if fn.Name() == "helper" {
			helper = fn
		}
		if fn.Name() != "main" {
			continue
		}
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				switch v := instr.(type) {
				case *ssa.Call:
					if c := v.Call.StaticCallee(); c != nil && c.Name() == "helper" {
						call = v
					}
				case *ssa.Lookup:
					lookup = v
				}
			}
		}
	}
	return helper, call, lookup
}

func helperSummaryEvents(fn *ssa.Function, call *ssa.Call, lookup *ssa.Lookup) []mapEvent {
	args := callParamArgs(fn, call)
	return calleeMapEvents(fn, map[ssa.Value]struct{}{fn.Params[0]: {}}, lookup, func(v ssa.Value) ssa.Value { return resolveWithParamArgs(v, args) }, defaultMaxSummaryDepth, nil)
}

func TestHelperMapBoundedShapes(t *testing.T) {
	for _, shape := range []string{"Diamonds", "Loops"} {
		for _, n := range []int{0, 2, 4, 6, 8, 10, 12} {
			t.Run(fmt.Sprintf("%s/%d", shape, n), func(t *testing.T) {
				cg, pkg := detailedGraphForSource(t, helperSummaryProgram(shape, n))
				fn, call, lookup := helperSummaryQueries(cg)
				if fn == nil || call == nil || lookup == nil {
					t.Fatal("missing query")
				}
				events := helperSummaryEvents(fn, call, lookup)
				states := collectMapPathStates(events, calleeReturns(fn)[0])
				summary := directCalleeMapEventsWithLimit(call, lookup, 8)
				writes := 0
				for _, e := range summary {
					writes += len(e.values)
				}
				findings := CheckDetailed(cg, NewSources(pkg+".source"), NewSinks(pkg+".sink"))
				if len(findings) != 1 {
					t.Fatalf("findings=%d want 1", len(findings))
				}
				if !reflect.DeepEqual(findings, CheckDetailed(cg, NewSources(pkg+".source"), NewSinks(pkg+".sink"))) {
					t.Fatal("unstable diagnostics")
				}
				instrs := 0
				for _, block := range fn.Blocks {
					instrs += len(block.Instrs)
				}
				t.Logf("blocks=%d instructions=%d events=%d states=%d summary_values=%d findings=%d", len(fn.Blocks), instrs, len(events), len(states), writes, len(findings))
				if shape == "Diamonds" && len(states) != 1<<n {
					t.Fatalf("expected 2^%d states", n)
				}
			})
		}
	}
}

var helperSummarySummarySink []mapEvent

func BenchmarkHelperMapSummary(b *testing.B) {
	for _, shape := range []string{"Diamonds", "Loops"} {
		for _, n := range []int{0, 2, 4, 6, 8, 10, 12} {
			b.Run(fmt.Sprintf("%s/%d", shape, n), func(b *testing.B) {
				cg, _ := buildBenchCallGraph(b, helperSummaryProgram(shape, n))
				fn, call, lookup := helperSummaryQueries(cg)
				if fn == nil || call == nil || lookup == nil {
					b.Fatal("missing query")
				}
				states := collectMapPathStates(helperSummaryEvents(fn, call, lookup), calleeReturns(fn)[0])
				expected := directCalleeMapEventsWithLimit(call, lookup, 8)
				b.ReportAllocs()
				for b.Loop() {
					helperSummarySummarySink = directCalleeMapEventsWithLimit(call, lookup, 8)
				}
				if !reflect.DeepEqual(expected, helperSummarySummarySink) {
					b.Fatal("changed summary")
				}
				b.ReportMetric(float64(len(fn.Blocks)), "blocks")
				b.ReportMetric(float64(len(states)), "states")
			})
		}
	}
}

// Recorded mismatches below are inherited precision limitations, not desired
// semantics. A performance-only reducer must not silently change them.
func TestHelperMapPrecisionCharacterization(t *testing.T) {
	for _, tc := range []struct {
		name, helpers, body string
		observed, semantic  int
	}{
		{"direct_conditional_clear", `func helper(m map[string]string){if flag(){clear(m)}}`, `m:=map[string]string{"q":source()};helper(m);sink(m["q"])`, 1, 1},
		{"nested_conditional_clear", `func inner(m map[string]string){if flag(){clear(m)}};func helper(m map[string]string){inner(m)}`, `m:=map[string]string{"q":source()};helper(m);sink(m["q"])`, 0, 1},
		{"nested_conditional_delete", `func inner(m map[string]string){if flag(){delete(m,"q")}};func helper(m map[string]string){inner(m)}`, `m:=map[string]string{"q":source()};helper(m);sink(m["q"])`, 0, 1},
		{"direct_conditional_delete", `func helper(m map[string]string){if flag(){delete(m,"q")}}`, `m:=map[string]string{"q":source()};helper(m);sink(m["q"])`, 1, 1},
		{"nested_all_paths_clear", `func inner(m map[string]string){if flag(){clear(m)}else{delete(m,"q")}};func helper(m map[string]string){inner(m)}`, `m:=map[string]string{"q":source()};helper(m);sink(m["q"])`, 0, 0},
		{"helper_overwrite_clean", `func helper(m map[string]string){m["q"]="safe"}`, `m:=map[string]string{"q":source()};helper(m);sink(m["q"])`, 1, 0},
		{"helper_write_then_delete", `func helper(m map[string]string,v string){m["q"]=v;delete(m,"q")}`, `m:=make(map[string]string);helper(m,source());sink(m["q"])`, 0, 0},
		{"nested_write_then_delete", `func inner(m map[string]string,v string){m["q"]=v;delete(m,"q")};func helper(m map[string]string,v string){inner(m,v)}`, `m:=make(map[string]string);helper(m,source());sink(m["q"])`, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "package main\nfunc source() string{return \"user\"};func sink(string){};var unknown bool;func flag()bool{return unknown}\n" + tc.helpers + "\nfunc main(){" + tc.body + "}\n"
			cg, pkg := detailedGraphForSource(t, src)
			got := CheckDetailed(cg, NewSources(pkg+".source"), NewSinks(pkg+".sink"))
			t.Logf("observed=%d semantic_want=%d", len(got), tc.semantic)
			if len(got) != tc.observed {
				t.Fatalf("legacy characterization changed: recorded %d, observed %d; review semantic expectation before promoting", tc.observed, len(got))
			}
			if !reflect.DeepEqual(got, CheckDetailed(cg, NewSources(pkg+".source"), NewSinks(pkg+".sink"))) {
				t.Fatal("unstable diagnostics")
			}
		})
	}
}

// This has far more paths than a test can enumerate. Only the finite production
// reducer is called; the legacy oracle is intentionally confined to small CFGs.
func TestHelperMapManyDiamonds(t *testing.T) {
	cg, pkg := detailedGraphForSource(t, helperSummaryProgram("Diamonds", 64))
	_, call, lookup := helperSummaryQueries(cg)
	got := directCalleeMapEventsWithLimit(call, lookup, 8)
	if len(got) != 1 || got[0].kind != mapEventWrite || len(got[0].values) != 1 {
		t.Fatalf("unexpected summary: %#v", got)
	}
	if !reflect.DeepEqual(got, directCalleeMapEventsWithLimit(call, lookup, 8)) {
		t.Fatal("unstable summary")
	}
	if got := CheckDetailed(cg, NewSources(pkg+".source"), NewSinks(pkg+".sink")); len(got) != 1 {
		t.Fatalf("got %d diagnostics, want 1", len(got))
	}
}
