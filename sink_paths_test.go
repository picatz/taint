package taint

import (
	"context"
	"fmt"
	"go/token"
	"go/types"
	"math/rand/v2"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// These graphs are intentionally small and bounded, even if cancellation
// regresses. They have at most 4096 root-to-sink paths and execute no program.
func sinkDiamond(width, layers int) (*callgraph.Graph, *callgraph.Node) {
	prog := ssa.NewProgram(token.NewFileSet(), 0)
	sig := types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false)
	g := callgraph.New(prog.NewFunction("root", sig, "test"))
	previous := []*callgraph.Node{g.Root}
	for layer := 0; layer < layers; layer++ {
		next := make([]*callgraph.Node, width)
		for i := range next {
			next[i] = g.CreateNode(prog.NewFunction(fmt.Sprintf("n%d_%d", layer, i), sig, "test"))
			for _, parent := range previous {
				callgraph.AddEdge(parent, nil, next[i])
			}
		}
		previous = next
	}
	sink := g.CreateNode(prog.NewFunction("sink", sig, "test"))
	for _, parent := range previous {
		callgraph.AddEdge(parent, nil, sink)
	}
	return g, sink
}

func TestIndexedSinkPathsPreserveOrderAndCycles(t *testing.T) {
	g, sink := sinkDiamond(2, 3)
	// Preserve historical treatment of cycle-closing sink edges, duplicate
	// edges, malformed edges and disconnected nodes.
	callgraph.AddEdge(sink, nil, g.Root)
	g.Root.Out = append(g.Root.Out, g.Root.Out[0], nil, &callgraph.Edge{})
	unreachable := g.CreateNode(sink.Func.Prog.NewFunction("unreachable", sink.Func.Signature, "test"))
	callgraph.AddEdge(unreachable, nil, sink)
	rules := []sinkRule{
		{id: "sink", matchEdge: func(e *callgraph.Edge) bool { return e.Callee == sink }},
		{id: "root", matchEdge: func(e *callgraph.Edge) bool { return e.Callee == g.Root }},
		{id: "missing", matchEdge: func(*callgraph.Edge) bool { return false }},
		{id: "nil matcher"},
	}
	sites := indexSinkCallSites(context.Background(), g, rules)
	for i, rule := range rules {
		want := referenceSinkCallSitePaths(g, rule)
		got := findAllSinkCallSitePaths(context.Background(), g, sites[i])
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: ordered paths differ: got %d, want %d", rule.id, len(got), len(want))
		}
	}
	if _, ok := sites[0][unreachable.Out[0]]; ok {
		t.Fatal("indexed an unreachable sink edge")
	}
}

func TestSinkIndexMatchesSharedEdgesOnce(t *testing.T) {
	g, sink := sinkDiamond(2, 6)
	calls := map[*callgraph.Edge]int{}
	rules := []sinkRule{{id: "sink", matchEdge: func(e *callgraph.Edge) bool {
		calls[e]++
		return e.Callee == sink
	}}}
	sites := indexSinkCallSites(context.Background(), g, rules)
	paths := findAllSinkCallSitePaths(context.Background(), g, sites[0])
	if len(paths) != 64 {
		t.Fatalf("got %d paths, want 64", len(paths))
	}
	for edge, n := range calls {
		if n != 1 {
			t.Errorf("edge %v matched %d times, want once", edge, n)
		}
	}
}

func TestIndexedSinkPathsRandomGraphs(t *testing.T) {
	// Seven nodes bound even the densest fixture. Fixed seeds make a failure
	// reproducible; cycles and disconnected components are both allowed.
	for seed := uint64(0); seed < 32; seed++ {
		rng := rand.New(rand.NewPCG(1, seed))
		prog := ssa.NewProgram(token.NewFileSet(), 0)
		sig := types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false)
		g := callgraph.New(prog.NewFunction("root", sig, "test"))
		nodes := []*callgraph.Node{g.Root}
		for i := 1; i < 7; i++ {
			nodes = append(nodes, g.CreateNode(prog.NewFunction(fmt.Sprintf("n%d", i), sig, "test")))
		}
		for _, from := range nodes {
			for _, to := range nodes {
				if rng.IntN(4) == 0 {
					callgraph.AddEdge(from, nil, to)
				}
			}
		}
		var rules []sinkRule
		for _, target := range nodes {
			rules = append(rules, sinkRule{id: target.Func.Name(), matchEdge: func(e *callgraph.Edge) bool { return e.Callee == target }})
		}
		sites := indexSinkCallSites(context.Background(), g, rules)
		for i, rule := range rules {
			got := findAllSinkCallSitePaths(context.Background(), g, sites[i])
			want := referenceSinkCallSitePaths(g, rule)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("seed %d sink %s: ordered paths differ", seed, rule.id)
			}
		}
	}
}

func BenchmarkSinkDiscoveryNoMatches(b *testing.B) {
	// At most 4096 paths: the legacy checker must not be given an unbounded
	// exponential stress graph just to demonstrate the no-match fast path.
	cg, _ := sinkDiamond(2, 12)
	var ids []string
	for i := range 16 {
		ids = append(ids, fmt.Sprintf("missing.Sink%d", i))
	}
	sources, sinks := NewSources(), NewSinks(ids...)
	for _, version := range []string{"reference", "indexed"} {
		b.Run(version, func(b *testing.B) {
			if version == "reference" {
				for b.Loop() {
					benchDiagnosticsSink = referenceCheckDetailed(cg, sources, sinks)
				}
			} else {
				for b.Loop() {
					benchDiagnosticsSink = CheckDetailed(cg, sources, sinks)
				}
			}
			if len(benchDiagnosticsSink) != 0 {
				b.Fatal("unmatched rules produced a diagnostic")
			}
		})
	}
}

// budgetContext cancels deterministically at an Err checkpoint, avoiding
// sleeps, racing goroutines, and giant exponential fixtures in cancellation
// tests. It delegates Done and Err state to a real cancellable context.
type budgetContext struct {
	context.Context
	cancel context.CancelFunc
	limit  int64
	checks atomic.Int64
}

func newBudgetContext(t *testing.T, limit int64) *budgetContext {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &budgetContext{Context: ctx, cancel: cancel, limit: limit}
}

func (c *budgetContext) Err() error {
	if c.checks.Add(1) >= c.limit {
		c.cancel()
	}
	return c.Context.Err()
}

func TestSinkIndexHonorsCancellation(t *testing.T) {
	g, sink := sinkDiamond(2, 12)
	ctx := newBudgetContext(t, 8)
	rule := sinkRule{id: "sink", matchEdge: func(e *callgraph.Edge) bool { return e.Callee == sink }}
	indexSinkCallSites(ctx, g, []sinkRule{rule})
	if ctx.Context.Err() != context.Canceled || ctx.checks.Load() > 10 {
		t.Fatalf("discovery did not stop promptly: err=%v checks=%d", ctx.Context.Err(), ctx.checks.Load())
	}
}

func TestSinkPathDFSHonorsCancellation(t *testing.T) {
	g, sink := sinkDiamond(2, 12)
	rule := sinkRule{id: "sink", matchEdge: func(e *callgraph.Edge) bool { return e.Callee == sink }}
	sites := indexSinkCallSites(context.Background(), g, []sinkRule{rule})
	ctx := newBudgetContext(t, 80)
	paths := findAllSinkCallSitePaths(ctx, g, sites[0])
	if ctx.Context.Err() != context.Canceled {
		t.Fatal("DFS did not check cancellation")
	}
	if len(paths) == 0 || len(paths) >= 4096 || ctx.checks.Load() > 100 {
		t.Fatalf("DFS did not stop during enumeration: paths=%d checks=%d", len(paths), ctx.checks.Load())
	}
}

func TestUnmatchedSinkSkipsPathEnumeration(t *testing.T) {
	g, _ := sinkDiamond(2, 12)
	ctx := newBudgetContext(t, 1)
	if paths := findAllSinkCallSitePaths(ctx, g, nil); len(paths) != 0 {
		t.Fatalf("unexpected paths: %d", len(paths))
	}
	if ctx.checks.Load() != 0 {
		t.Fatal("an unmatched rule entered DFS")
	}
}

func TestSinkDiscoveryEmptyGraphs(t *testing.T) {
	for _, cg := range []*callgraph.Graph{nil, {}} {
		sites := indexSinkCallSites(context.Background(), cg, []sinkRule{{id: "missing"}})
		if len(sites) != 1 || len(sites[0]) != 0 {
			t.Fatalf("unexpected empty graph index: %v", sites)
		}
		if got := findAllSinkCallSitePaths(context.Background(), cg, sites[0]); len(got) != 0 {
			t.Fatalf("unexpected empty graph paths: %v", got)
		}
	}
}

func TestIndexedDiscoveryDiagnosticEquivalence(t *testing.T) {
	tests := []struct {
		name  string
		src   string
		sinks []string
		want  int
		opts  func(string) []Option
	}{
		{"direct and clean", `func sink(string) {}; func main() { sink(source()); sink("clean") }`, []string{"$.sink"}, 1, nil},
		{"equal witness paths", `func sink(string) {}; func helper(v string) { sink(v) }; func left(v string) { helper(v) }; func right(v string) { helper(v) }; func main() { left(source()); right(source()) }`, []string{"$.sink"}, 1, nil},
		{"interface and concrete rules", `type output interface { Write(string) }; type writer struct{}; func (writer) Write(string) {}; func invoke(w output,v string) { w.Write(v) }; func main() { invoke(writer{},source()) }`, []string{"($.output).Write", "($.writer).Write"}, 1, nil},
		{"bound method", `type writer struct{}; func (*writer) Write(string) {}; func main() { w := &writer{}; f := w.Write; f(source()) }`, []string{"(*$.writer).Write"}, 1, nil},
		{"callback", `func sink(string) {}; func invoke(f func(string),v string) { f(v) }; func main() { invoke(sink, source()) }`, []string{"$.sink"}, 1, nil},
		{"generic receiver", `type writer[T any] struct{}; func (writer[T]) Write(string) {}; func main() { writer[int]{}.Write(source()) }`, []string{"($.writer[int]).Write"}, 1, nil},
		{"sanitizer evidence", `func sink(string) {}; func escape(v string) string { return v }; func main() { sink(escape(source()) + source()); sink(escape(source())) }`, []string{"$.sink"}, 1, func(pkg string) []Option { return []Option{WithSanitizers(pkg + ".escape")} }},
		{"duplicate model ids", `func sink(string,string) {}; func main() { sink("clean",source()) }`, nil, 1, func(pkg string) []Option {
			return []Option{WithModels(Model{Package: pkg, Sinks: []SinkModel{
				{Method: pkg + ".sink", Args: []ArgSelector{Arg(0)}},
				{Method: pkg + ".sink", Args: []ArgSelector{Arg(1)}},
			}})}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cg, pkg := detailedGraphForSource(t, "package main\nfunc source() string { return \"user\" }\n"+tt.src)
			var ids []string
			for _, id := range tt.sinks {
				ids = append(ids, strings.ReplaceAll(id, "$", pkg))
			}
			var opts []Option
			if tt.opts != nil {
				opts = tt.opts(pkg)
			}
			assertDiscoveryDiagnosticsEqual(t, cg, NewSources(pkg+".source"), NewSinks(ids...), tt.want, opts...)
		})
	}
}

func assertDiscoveryDiagnosticsEqual(t *testing.T, cg *callgraph.Graph, sources Sources, sinks Sinks, count int, opts ...Option) {
	t.Helper()
	want := referenceCheckDetailed(cg, sources, sinks, opts...)
	if len(want) != count {
		t.Fatalf("reference fixture has %d diagnostics, want %d", len(want), count)
	}
	got := CheckDetailed(cg, sources, sinks, opts...)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("diagnostics or ordered evidence changed: got %d, want %d diagnostics", len(got), len(want))
	}
}

func TestCheckDetailedCanceledDiscovery(t *testing.T) {
	cg, pkg := detailedGraphForSource(t, `package main
func source() string { return "user" }
func sink(string) {}
func main() { sink(source()) }
`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assertDiscoveryDiagnosticsEqual(t, cg, NewSources(pkg+".source"), NewSinks(pkg+".sink"), 0, WithContext(ctx))
}
