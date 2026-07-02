package taint

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/picatz/taint/callgraphutil"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// benchDiagnosticsSink is a package-level landing spot for CheckDetailed
// results computed inside a benchmark loop. Assigning to it (rather than a
// local that the compiler could prove dead) keeps the call from being
// optimized away.
var benchDiagnosticsSink Diagnostics

// buildBenchCallGraph loads a single-file main package from src and builds
// its SSA callgraph. It mirrors the loading pattern used by
// detailedGraphForSource in check_detailed_test.go (packages.Load in a
// GOPATH-free temp module, ssautil.Packages with ssa.InstantiateGenerics,
// then callgraphutil.NewGraph), but is a self-contained copy so this file has
// no dependency on the test helpers in check_detailed_test.go. It returns the
// built graph and the package path of the generated main package, which
// callers need to qualify source identifiers (e.g. pkgPath+".source").
//
// Callers should build the graph once, outside of b.Loop(), so only
// CheckDetailed itself is measured.
func buildBenchCallGraph(b *testing.B, src string) (*callgraph.Graph, string) {
	b.Helper()

	dir := b.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/bench\n\ngo 1.24.4\n"), 0o644); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		b.Fatal(err)
	}

	pkgs, err := packages.Load(&packages.Config{
		Mode: packages.NeedName |
			packages.NeedDeps |
			packages.NeedFiles |
			packages.NeedCompiledGoFiles |
			packages.NeedTypes |
			packages.NeedImports |
			packages.NeedSyntax |
			packages.NeedTypesInfo,
		Context: context.Background(),
		Dir:     dir,
		Tests:   false,
	}, "./...")
	if err != nil {
		b.Fatal(err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		b.Fatal("package load failed")
	}

	ssaProg, ssaPkgs := ssautil.Packages(pkgs, ssa.InstantiateGenerics)
	ssaProg.Build()
	for _, pkg := range ssaPkgs {
		pkg.Build()
	}

	mainPkgs := ssautil.MainPackages(ssaPkgs)
	if len(mainPkgs) != 1 {
		b.Fatalf("expected one main package, got %d", len(mainPkgs))
	}
	mainFn := mainPkgs[0].Func("main")
	if mainFn == nil {
		b.Fatal("main function not found")
	}

	var srcFns []*ssa.Function
	var addFunction func(*ssa.Function)
	addFunction = func(fn *ssa.Function) {
		srcFns = append(srcFns, fn)
		for _, anon := range fn.AnonFuncs {
			addFunction(anon)
		}
	}
	for _, pkg := range ssaPkgs {
		for _, member := range pkg.Members {
			fn, ok := member.(*ssa.Function)
			if !ok || fn.Object() == nil || fn.Object().Name() == "_" {
				continue
			}
			addFunction(fn)
		}
	}

	cg, err := callgraphutil.NewGraph(mainFn, srcFns...)
	if err != nil {
		b.Fatal(err)
	}
	return cg, mainFn.Pkg.Pkg.Path()
}

// countSinkPaths runs the same enumeration CheckDetailed performs
// (findAllSinkCallSitePaths, once per sink rule) and returns the total number
// of root-to-sink-callsite simple paths across every rule. It exists purely
// to attach an informational b.ReportMetric to a benchmark and must only be
// called outside the timed loop.
func countSinkPaths(cg *callgraph.Graph, sources Sources, sinks Sinks) int {
	rules := newRuleRegistry(sources, sinks, defaultCheckConfig())
	total := 0
	for _, sink := range rules.sinkRules {
		total += len(findAllSinkCallSitePaths(cg, sink))
	}
	return total
}

// genLinearSource generates a program with a linear call chain
// main -> f1 -> f2 -> ... -> fDepth, where fDepth calls the sink
// (*database/sql.DB).Query with a value threaded, unchanged, from a local
// source() function all the way down the chain. There is exactly one path
// from the callgraph root to the sink call site regardless of depth, so this
// isolates the cost of a single, long backward SSA walk from the cost of
// enumerating many paths (see genDiamondSource).
func genLinearSource(depth int) string {
	var sb strings.Builder
	sb.WriteString("package main\n\n")
	sb.WriteString("import \"database/sql\"\n\n")
	sb.WriteString("func source() string { return \"tainted\" }\n\n")
	for i := 1; i <= depth; i++ {
		fmt.Fprintf(&sb, "func f%d(s string) string {\n", i)
		if i < depth {
			fmt.Fprintf(&sb, "\treturn f%d(s)\n", i+1)
		} else {
			sb.WriteString("\tdb := &sql.DB{}\n")
			sb.WriteString("\tdb.Query(s)\n")
			sb.WriteString("\treturn s\n")
		}
		sb.WriteString("}\n\n")
	}
	sb.WriteString("func main() {\n\tf1(source())\n}\n")
	return sb.String()
}

// genDiamondSource generates a layered callgraph shaped like the diamond
// gosec and this engine's own findAllSinkCallSitePaths choke on: `layers`
// stacked layers of `width` functions each, where every function in layer i
// calls every function in layer i+1 (a complete bipartite fan-out/fan-in
// between consecutive layers), and every function in the final layer calls
// the sink with the tainted value threaded in from main. The number of
// distinct simple root-to-sink paths this produces is width^layers, since
// each of the `layers` hops independently picks one of `width` next-layer
// functions.
func genDiamondSource(width, layers int) string {
	var sb strings.Builder
	sb.WriteString("package main\n\n")
	sb.WriteString("import \"database/sql\"\n\n")
	sb.WriteString("func source() string { return \"tainted\" }\n\n")

	for layer := 1; layer <= layers; layer++ {
		for fn := 1; fn <= width; fn++ {
			fmt.Fprintf(&sb, "func l%d_%d(s string) {\n", layer, fn)
			if layer < layers {
				for next := 1; next <= width; next++ {
					fmt.Fprintf(&sb, "\tl%d_%d(s)\n", layer+1, next)
				}
			} else {
				sb.WriteString("\tdb := &sql.DB{}\n")
				sb.WriteString("\tdb.Query(s)\n")
			}
			sb.WriteString("}\n\n")
		}
	}

	sb.WriteString("func main() {\n")
	for fn := 1; fn <= width; fn++ {
		fmt.Fprintf(&sb, "\tl1_%d(source())\n", fn)
	}
	sb.WriteString("}\n")
	return sb.String()
}

// genManySinksProgram generates a single fixed program with exactly one real
// source-to-sink flow. It is reused, unchanged, across BenchmarkCheckDetailedManySinks
// sub-benchmarks; only the Sinks set passed to CheckDetailed varies, isolating
// the cost of the per-sink-rule full-graph re-enumeration that
// findAllSinkCallSitePaths performs once per rule in rules.sinkRules.
func genManySinksProgram() string {
	return `package main

import "database/sql"

func source() string { return "tainted" }

func handler(s string) {
	db := &sql.DB{}
	db.Query(s)
}

func main() {
	handler(source())
}
`
}

// manySinksSet returns a Sinks set with n total entries: the one sink rule
// that actually matches the program built by genManySinksProgram, plus n-1
// distinct, never-matching filler rules. Every rule, matching or not, forces
// its own full findAllSinkCallSitePaths traversal of the graph, so growing n
// measures pure per-rule re-enumeration overhead.
func manySinksSet(n int) Sinks {
	ids := make([]string, 0, n)
	ids = append(ids, "(*database/sql.DB).Query")
	for i := 0; i < n-1; i++ {
		ids = append(ids, fmt.Sprintf("bench/fakepkg.FakeSink%d", i))
	}
	return NewSinks(ids...)
}

// genManyDiagnosticsProgram generates n independent handler functions, each
// with its own direct source-to-sink flow, all called from main. Unlike
// genDiamondSource there is no shared structure between handlers, so path
// enumeration stays O(n); this isolates the cost of building and
// deduplicating n separate Diagnostic entries (evidence trails included).
func genManyDiagnosticsProgram(n int) string {
	var sb strings.Builder
	sb.WriteString("package main\n\n")
	sb.WriteString("import \"database/sql\"\n\n")
	sb.WriteString("func source() string { return \"tainted\" }\n\n")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&sb, "func handler%d() {\n\tdb := &sql.DB{}\n\tdb.Query(source())\n}\n\n", i)
	}
	sb.WriteString("func main() {\n")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&sb, "\thandler%d()\n", i)
	}
	sb.WriteString("}\n")
	return sb.String()
}

// BenchmarkCheckDetailedLinear measures CheckDetailed on a single long
// backward-walk chain (one path, increasing depth), as a baseline against
// which the diamond shape's growth is compared.
func BenchmarkCheckDetailedLinear(b *testing.B) {
	for _, depth := range []int{4, 8, 16} {
		b.Run(fmt.Sprintf("depth-%d", depth), func(b *testing.B) {
			cg, pkgPath := buildBenchCallGraph(b, genLinearSource(depth))
			sources := NewSources(pkgPath + ".source")
			sinks := NewSinks("(*database/sql.DB).Query")

			for b.Loop() {
				benchDiagnosticsSink = CheckDetailed(cg, sources, sinks)
			}
		})
	}
}

// BenchmarkCheckDetailedDiamond measures CheckDetailed on the path-explosion
// shape described in docs/design/scalable-checking.md: N handlers funnelling
// through shared helper layers into a single sink rule. width^layers distinct
// simple paths are enumerated and independently walked, so this benchmark is
// the primary evidence for the planned per-callsite rework.
func BenchmarkCheckDetailedDiamond(b *testing.B) {
	widths := []int{2, 4, 8}
	layerCounts := []int{2, 3}

	for _, layers := range layerCounts {
		for _, width := range widths {
			b.Run(fmt.Sprintf("%dx%d", width, layers), func(b *testing.B) {
				cg, pkgPath := buildBenchCallGraph(b, genDiamondSource(width, layers))
				sources := NewSources(pkgPath + ".source")
				sinks := NewSinks("(*database/sql.DB).Query")
				paths := countSinkPaths(cg, sources, sinks)

				for b.Loop() {
					benchDiagnosticsSink = CheckDetailed(cg, sources, sinks)
				}

				// Reported after b.Loop() finishes: ReportMetric calls made
				// before the loop starts are discarded when the timer resets.
				b.ReportMetric(float64(paths), "paths")
			})
		}
	}
}

// BenchmarkCheckDetailedManySinks measures the cost of growing the Sinks set
// while only one rule actually matches, isolating the per-sink-rule
// full-graph re-enumeration findAllSinkCallSitePaths performs (once per rule
// in rules.sinkRules, per docs/design/scalable-checking.md).
func BenchmarkCheckDetailedManySinks(b *testing.B) {
	cg, pkgPath := buildBenchCallGraph(b, genManySinksProgram())
	sources := NewSources(pkgPath + ".source")

	for _, n := range []int{1, 4, 16} {
		b.Run(fmt.Sprintf("sinks-%d", n), func(b *testing.B) {
			sinks := manySinksSet(n)

			for b.Loop() {
				benchDiagnosticsSink = CheckDetailed(cg, sources, sinks)
			}
		})
	}
}

// BenchmarkCheckDetailedManyDiagnostics measures CheckDetailed on a wide but
// shallow program: 20 independent handlers, each with its own real
// source-to-sink flow, so the benchmark is dominated by diagnostic
// construction and deduplication rather than path enumeration.
func BenchmarkCheckDetailedManyDiagnostics(b *testing.B) {
	const handlers = 20

	cg, pkgPath := buildBenchCallGraph(b, genManyDiagnosticsProgram(handlers))
	sources := NewSources(pkgPath + ".source")
	sinks := NewSinks("(*database/sql.DB).Query")

	for b.Loop() {
		benchDiagnosticsSink = CheckDetailed(cg, sources, sinks)
	}
}
