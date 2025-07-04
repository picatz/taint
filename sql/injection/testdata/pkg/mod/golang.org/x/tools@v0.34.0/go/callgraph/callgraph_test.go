// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package callgraph_test

import (
	"sync"
	"testing"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/callgraph/static"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"golang.org/x/tools/internal/testfiles"
	"golang.org/x/tools/txtar"
)

// Benchmarks comparing different callgraph algorithms implemented in
// x/tools/go/callgraph. Comparison is on both speed, memory and precision.
// Fewer edges and fewer reachable nodes implies a more precise result.
// Comparison is done on a hello world http server using net/http.
//
// Current results were on an i7 macbook on go version devel go1.20-2730.
// Number of nodes, edges, and reachable function are expected to vary between
// go versions. Timing results are expected to vary between machines.
// BenchmarkStatic-12	 53 ms/op     6 MB/op	12113 nodes	 37355 edges	1522 reachable
// BenchmarkCHA-12    	 86 ms/op	 16 MB/op	12113 nodes	131717 edges	7640 reachable
// BenchmarkRTA-12		110 ms/op	 12 MB/op	 6566 nodes	 42291 edges	5099 reachable
// BenchmarkPTA-12	   1427 ms/op	600 MB/op	 8714 nodes	 28244 edges	4184 reachable
// BenchmarkVTA-12		600 ms/op	 78 MB/op	12114 nodes	 44861 edges	4919 reachable
// BenchmarkVTA2-12		793 ms/op	104 MB/op	 5450 nodes	 22208 edges	4042 reachable
// BenchmarkVTA3-12		977 ms/op	124 MB/op	 4621 nodes	 19331 edges	3700 reachable
// BenchmarkVTAAlt-12	372 ms/op	 57 MB/op	 7763 nodes	 29912 edges	4258 reachable
// BenchmarkVTAAlt2-12	570 ms/op	 78 MB/op	 4838 nodes	 20169 edges	3737 reachable
//
// Note:
// * Static is unsound and may miss real edges.
// * RTA starts from a main function and only includes reachable functions.
// * CHA starts from all functions.
// * VTA, VTA2, and VTA3 are starting from all functions and the CHA callgraph.
//   VTA2 and VTA3 are the result of re-applying VTA to the functions reachable
//   from main() via the callgraph of the previous stage.
// * VTAAlt, and VTAAlt2 start from the functions reachable from main via the
//   CHA callgraph.
// * All algorithms are unsound w.r.t. reflection.

const httpEx = `
-- go.mod --
module x.io

-- main.go --
package main

import (
    "fmt"
    "net/http"
)

func hello(w http.ResponseWriter, req *http.Request) {
    fmt.Fprintf(w, "hello world\n")
}

func main() {
    http.HandleFunc("/hello", hello)
    http.ListenAndServe(":8090", nil)
}
`

var (
	once sync.Once
	main *ssa.Function
)

func example(t testing.TB) (*ssa.Program, *ssa.Function) {
	once.Do(func() {
		pkgs := testfiles.LoadPackages(t, txtar.Parse([]byte(httpEx)), ".")
		prog, ssapkgs := ssautil.Packages(pkgs, ssa.InstantiateGenerics)
		prog.Build()
		main = ssapkgs[0].Members["main"].(*ssa.Function)
	})
	return main.Prog, main
}

var stats bool = false // print stats?

func logStats(b *testing.B, cnd bool, name string, cg *callgraph.Graph, main *ssa.Function) {
	if cnd && stats {
		e := 0
		for _, n := range cg.Nodes {
			e += len(n.Out)
		}
		r := len(reaches(main, cg, false))
		b.Logf("%s:\t%d nodes\t%d edges\t%d reachable", name, len(cg.Nodes), e, r)
	}
}

func BenchmarkStatic(b *testing.B) {
	b.StopTimer()
	prog, main := example(b)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		cg := static.CallGraph(prog)
		logStats(b, i == 0, "static", cg, main)
	}
}

func BenchmarkCHA(b *testing.B) {
	b.StopTimer()
	prog, main := example(b)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		cg := cha.CallGraph(prog)
		logStats(b, i == 0, "cha", cg, main)
	}
}

func BenchmarkRTA(b *testing.B) {
	b.StopTimer()
	_, main := example(b)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		res := rta.Analyze([]*ssa.Function{main}, true)
		cg := res.CallGraph
		logStats(b, i == 0, "rta", cg, main)
	}
}

func BenchmarkVTA(b *testing.B) {
	b.StopTimer()
	prog, main := example(b)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		cg := vta.CallGraph(ssautil.AllFunctions(prog), cha.CallGraph(prog))
		logStats(b, i == 0, "vta", cg, main)
	}
}

func BenchmarkVTA2(b *testing.B) {
	b.StopTimer()
	prog, main := example(b)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		vta1 := vta.CallGraph(ssautil.AllFunctions(prog), cha.CallGraph(prog))
		cg := vta.CallGraph(reaches(main, vta1, true), vta1)
		logStats(b, i == 0, "vta2", cg, main)
	}
}

func BenchmarkVTA3(b *testing.B) {
	b.StopTimer()
	prog, main := example(b)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		vta1 := vta.CallGraph(ssautil.AllFunctions(prog), cha.CallGraph(prog))
		vta2 := vta.CallGraph(reaches(main, vta1, true), vta1)
		cg := vta.CallGraph(reaches(main, vta2, true), vta2)
		logStats(b, i == 0, "vta3", cg, main)
	}
}

func BenchmarkVTAAlt(b *testing.B) {
	b.StopTimer()
	prog, main := example(b)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		cha := cha.CallGraph(prog)
		cg := vta.CallGraph(reaches(main, cha, true), cha) // start from only functions reachable by CHA.
		logStats(b, i == 0, "vta-alt", cg, main)
	}
}

func BenchmarkVTAAlt2(b *testing.B) {
	b.StopTimer()
	prog, main := example(b)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		cha := cha.CallGraph(prog)
		vta1 := vta.CallGraph(reaches(main, cha, true), cha)
		cg := vta.CallGraph(reaches(main, vta1, true), vta1)
		logStats(b, i == 0, "vta-alt2", cg, main)
	}
}

// reaches computes the transitive closure of functions forward reachable
// via calls in cg starting from `sources`. If refs is true, include
// functions referred to in an instruction.
func reaches(source *ssa.Function, cg *callgraph.Graph, refs bool) map[*ssa.Function]bool {
	seen := make(map[*ssa.Function]bool)
	var visit func(f *ssa.Function)
	visit = func(f *ssa.Function) {
		if seen[f] {
			return
		}
		seen[f] = true

		if n := cg.Nodes[f]; n != nil {
			for _, e := range n.Out {
				if e.Site != nil {
					visit(e.Callee.Func)
				}
			}
		}

		if refs {
			var buf [10]*ssa.Value // avoid alloc in common case
			for _, b := range f.Blocks {
				for _, instr := range b.Instrs {
					for _, op := range instr.Operands(buf[:0]) {
						if fn, ok := (*op).(*ssa.Function); ok {
							visit(fn)
						}
					}
				}
			}
		}
	}
	visit(source)
	return seen
}
