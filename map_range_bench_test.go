package taint

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/tools/go/ssa"
)

var benchMapRangeValuesSink []ssa.Value

// All fixtures are analyzed statically; no fixture loop is executed or unrolled.
// SSA loading, count validation, and evidence validation are outside b.Loop.
// Reported writes count static MapUpdate statements, not runtime iterations.
func BenchmarkCheckDetailedMapRange(b *testing.B) {
	for _, size := range []int{1, 16, 128, 1024} {
		for _, shape := range []string{"Values", "CleanValues", "LoopBackedge", "OverwriteHeavy", "DeleteHeavy", "ManyReads"} {
			b.Run(fmt.Sprintf("%s/%d", shape, size), func(b *testing.B) {
				src, findings, writes, reads := mapRangeBenchmarkProgram(shape, size)
				cg, pkg := buildBenchCallGraph(b, src)
				sources, sinks := NewSources(pkg+".source"), NewSinks(pkg+".sink")
				want := CheckDetailed(cg, sources, sinks)
				if len(want) != findings {
					b.Fatalf("fixture got %d findings, want %d", len(want), findings)
				}
				for _, d := range want {
					if d.Result.SourceType != pkg+".source" || d.Result.SourceValue == nil || d.Result.SourceValue.String() != pkg+".source" || d.Result.SinkType != pkg+".sink" || !d.Result.ReportPos().IsValid() {
						b.Fatalf("fixture has incorrect attribution: %+v", d.Result)
					}
				}
				if got := CheckDetailed(cg, sources, sinks); !reflect.DeepEqual(got, want) {
					b.Fatal("fixture diagnostics/evidence are not deterministic")
				}
				paths := countSinkPaths(cg, sources, sinks)
				instructions := 0
				for fn := range cg.Nodes {
					if fn == nil {
						continue
					}
					for _, block := range fn.Blocks {
						instructions += len(block.Instrs)
					}
				}
				b.ReportAllocs()
				for b.Loop() {
					benchDiagnosticsSink = CheckDetailed(cg, sources, sinks)
				}
				if !reflect.DeepEqual(benchDiagnosticsSink, want) {
					b.Fatal("timed result changed diagnostics/evidence")
				}
				b.ReportMetric(float64(len(benchDiagnosticsSink)), "findings")
				b.ReportMetric(float64(paths), "paths")
				b.ReportMetric(float64(writes), "writes")
				b.ReportMetric(float64(reads), "reads")
				b.ReportMetric(float64(instructions), "ssa-instrs")
			})
		}
	}
}

// This isolates map-entry reaching definitions from sink indexing, call-path
// enumeration, scalar taint traversal, and evidence assembly. Each operation
// analyzes every range in the fixture once, so ManyReads still reflects the
// cost of independent read queries in a larger function.
func BenchmarkMapRangeReachingValues(b *testing.B) {
	for _, size := range []int{1, 16, 128, 1024} {
		for _, shape := range []string{"Values", "CleanValues", "LoopBackedge", "OverwriteHeavy", "DeleteHeavy", "ManyReads"} {
			b.Run(fmt.Sprintf("%s/%d", shape, size), func(b *testing.B) {
				src, _, writes, reads := mapRangeBenchmarkProgram(shape, size)
				cg, _ := buildBenchCallGraph(b, src)
				type query struct {
					mapv ssa.Value
					use  *ssa.Next
					want []ssa.Value
				}
				var queries []query
				candidates, instructions := 0, 0
				for fn := range cg.Nodes {
					if fn == nil {
						continue
					}
					for _, block := range fn.Blocks {
						instructions += len(block.Instrs)
						for _, instr := range block.Instrs {
							next, ok := instr.(*ssa.Next)
							if !ok || next.IsString {
								continue
							}
							rangev, ok := next.Iter.(*ssa.Range)
							if !ok {
								b.Fatal("unexpected map iterator origin")
							}
							want := reachingMapRangeValues(rangev.X, next, 2)
							if got := reachingMapRangeValues(rangev.X, next, 2); !reflect.DeepEqual(got, want) {
								b.Fatal("unstable reaching-value order")
							}
							queries = append(queries, query{rangev.X, next, want})
							candidates += len(want)
						}
					}
				}
				if len(queries) != reads {
					b.Fatalf("got %d SSA reads, want %d", len(queries), reads)
				}
				b.ReportAllocs()
				for b.Loop() {
					for _, q := range queries {
						benchMapRangeValuesSink = reachingMapRangeValues(q.mapv, q.use, 2)
					}
				}
				if !reflect.DeepEqual(benchMapRangeValuesSink, queries[len(queries)-1].want) {
					b.Fatal("timed result changed reaching-value order")
				}
				b.ReportMetric(float64(candidates), "candidates")
				b.ReportMetric(float64(writes), "writes")
				b.ReportMetric(float64(reads), "reads")
				b.ReportMetric(float64(instructions), "ssa-instrs")
			})
		}
	}
}

func mapRangeBenchmarkProgram(shape string, size int) (src string, findings, writes, reads int) {
	var body strings.Builder
	body.WriteString("payload := source(); _ = payload\nm := make(map[string]string)\n")
	reads = 1
	switch shape {
	case "Values", "CleanValues":
		for i := 0; i < size; i++ {
			value := `"safe"`
			if shape == "Values" && i == size-1 {
				value = "payload"
				findings = 1
			}
			fmt.Fprintf(&body, "m[%q] = %s\n", fmt.Sprintf("k%d", i), value)
		}
		writes = size
		body.WriteString("for _, v := range m { sink(v) }\n")
	case "LoopBackedge":
		body.WriteString("m[\"seed0\"] = \"safe\"\nm[\"seed1\"] = \"safe\"\nfor _, v := range m {\nsink(v)\n")
		for i := 0; i < size; i++ {
			value := `"safe"`
			if i == size-1 {
				value = "payload"
			}
			fmt.Fprintf(&body, "m[%q] = %s\n", fmt.Sprintf("k%d", i), value)
		}
		body.WriteString("}\n")
		findings, writes = 1, size+2
	case "OverwriteHeavy", "DeleteHeavy":
		for i := 0; i < size; i++ {
			key := fmt.Sprintf("k%d", i)
			fmt.Fprintf(&body, "m[%q] = payload\n", key)
			writes++
			if shape == "OverwriteHeavy" {
				fmt.Fprintf(&body, "m[%q] = \"safe\"\n", key)
				writes++
			} else {
				fmt.Fprintf(&body, "delete(m, %q)\n", key)
			}
		}
		body.WriteString("for _, v := range m { sink(v) }\n")
	case "ManyReads":
		// Hold map size fixed while varying the number of independent reads.
		for i := 0; i < 16; i++ {
			value := `"safe"`
			if i == 15 {
				value = "payload"
			}
			fmt.Fprintf(&body, "m[%q] = %s\n", fmt.Sprintf("k%d", i), value)
		}
		for i := 0; i < size; i++ {
			body.WriteString("for _, v := range m { sink(v) }\n")
		}
		findings, writes, reads = size, 16, size
	default:
		panic("unknown map-range benchmark shape: " + shape)
	}
	return "package main\nfunc source() string { return \"input\" }\nfunc sink(string) {}\nfunc main() {\n" + body.String() + "}\n", findings, writes, reads
}
