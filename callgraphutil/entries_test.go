package callgraphutil

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"
	"testing"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// Build real SSA, including the Object()==nil package initializer. Nothing here
// depends on loading dependencies or changing the detector's scanner scope.
func exactEntryFixture(t *testing.T) (*ssa.Program, map[string]*ssa.Function) {
	t.Helper()
	fset := token.NewFileSet()
	prog := ssa.NewProgram(fset, ssa.InstantiateGenerics)
	functions := make(map[string]*ssa.Function)
	for _, spec := range []struct{ path, source string }{
		{"example/a", `package main
var initialized = initTarget()
func initTarget() int { return 1 }
func main() { mainTarget() }
func mainTarget() {}
func hidden() { hiddenTarget() }
func hiddenTarget() {}
func factory() func() { return func() { closureTarget() } }
func closureTarget() {}
`},
		{"example/b", `package main
func main() { target() }
func target() {}
`},
		{"example/lib", `package lib
func Exported() { target() }
func target() {}
func Unselected() { unrelated() }
func unrelated() {}
`},
	} {
		file, err := parser.ParseFile(fset, spec.path+".go", spec.source, 0)
		if err != nil {
			t.Fatal(err)
		}
		info := &types.Info{Types: make(map[ast.Expr]types.TypeAndValue), Defs: make(map[*ast.Ident]types.Object), Uses: make(map[*ast.Ident]types.Object), Implicits: make(map[ast.Node]types.Object), Scopes: make(map[ast.Node]*types.Scope), Selections: make(map[*ast.SelectorExpr]*types.Selection)}
		pkg, err := new(types.Config).Check(spec.path, fset, []*ast.File{file}, info)
		if err != nil {
			t.Fatal(err)
		}
		sp := prog.CreatePackage(pkg, []*ast.File{file}, info, true)
		sp.Build()
		for name, member := range sp.Members {
			if fn, ok := member.(*ssa.Function); ok {
				functions[spec.path+"."+name] = fn
			}
		}
	}
	functions["closure"] = functions["example/a.factory"].AnonFuncs[0]
	return prog, functions
}

func assertExactRoot(t *testing.T, g *callgraph.Graph, root *ssa.Function, want []*ssa.Function) {
	t.Helper()
	if g == nil || g.Root == nil || g.Root.Func != root || g.Nodes[root] != g.Root {
		t.Fatal("missing synthetic root")
	}
	if len(g.Root.Out) != len(want) {
		t.Fatalf("root has %d edges, want %d", len(g.Root.Out), len(want))
	}
	seen := make(map[*ssa.Function]bool)
	for _, e := range g.Root.Out {
		if e.Site != nil || e.Caller != g.Root {
			t.Fatal("invalid synthetic-root edge")
		}
		if seen[e.Callee.Func] {
			t.Fatal("duplicate root edge")
		}
		seen[e.Callee.Func] = true
		found := false
		for _, in := range e.Callee.In {
			if in == e {
				found = true
			}
		}
		if !found {
			t.Fatal("missing reciprocal inbound edge")
		}
	}
	for _, fn := range want {
		if !seen[fn] {
			t.Fatalf("entry %s not rooted", fn)
		}
	}
}

func reachableExact(g *callgraph.Graph, fn *ssa.Function) bool {
	seen := map[*callgraph.Node]bool{}
	var visit func(*callgraph.Node) bool
	visit = func(n *callgraph.Node) bool {
		if seen[n] {
			return false
		}
		seen[n] = true
		if n.Func == fn {
			return true
		}
		for _, e := range n.Out {
			if visit(e.Callee) {
				return true
			}
		}
		return false
	}
	return visit(g.Root)
}

func TestCreateCallGraphFromEntries(t *testing.T) {
	prog, f := exactEntryFixture(t)
	if f["example/a.init"].Object() != nil {
		t.Fatal("fixture must have a synthetic initializer")
	}
	for _, tc := range []struct {
		name             string
		entries, targets []string
	}{
		{"init only", []string{"example/a.init"}, []string{"example/a.initTarget"}},
		{"closure only", []string{"closure"}, []string{"example/a.closureTarget"}},
		{"unexported only", []string{"example/a.hidden"}, []string{"example/a.hiddenTarget"}},
		{"multiple mains and library export", []string{"example/a.main", "example/b.main", "example/lib.Exported"}, []string{"example/a.mainTarget", "example/b.target", "example/lib.target"}},
		{"all explicit entries", []string{"example/a.init", "example/a.main", "example/b.main", "example/lib.Exported", "example/a.hidden", "closure"}, []string{"example/a.initTarget", "example/a.closureTarget", "example/a.hiddenTarget", "example/lib.target"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries := make([]*ssa.Function, 0, len(tc.entries))
			for _, name := range tc.entries {
				entries = append(entries, f[name])
			}
			g, root, err := CreateCallGraphFromEntries(context.Background(), prog, entries)
			if err != nil {
				t.Fatal(err)
			}
			assertExactRoot(t, g, root, entries)
			for _, name := range tc.targets {
				if !reachableExact(g, f[name]) {
					t.Fatalf("%s unreachable", name)
				}
			}
			if reachableExact(g, f["example/lib.Unselected"]) || reachableExact(g, f["example/lib.unrelated"]) {
				t.Fatal("unselected unrelated function became reachable")
			}
		})
	}
}

func TestCreateCallGraphFromEntriesDeduplicatesAndOrders(t *testing.T) {
	prog, f := exactEntryFixture(t)
	entries := []*ssa.Function{f["example/lib.Exported"], nil, f["example/a.init"], f["example/lib.Exported"], f["closure"]}
	original := append([]*ssa.Function(nil), entries...)
	var previous []*ssa.Function
	for i := 0; i < 8; i++ {
		g, root, err := CreateCallGraphFromEntries(context.Background(), prog, entries)
		if err != nil {
			t.Fatal(err)
		}
		assertExactRoot(t, g, root, []*ssa.Function{f["example/lib.Exported"], f["example/a.init"], f["closure"]})
		var order []*ssa.Function
		for _, e := range g.Root.Out {
			order = append(order, e.Callee.Func)
		}
		if previous != nil && !reflect.DeepEqual(order, previous) {
			t.Fatal("root ordering changed")
		}
		previous = order
		if i == 0 && !reflect.DeepEqual(entries, original) {
			t.Fatal("input mutated")
		}
		entries = append(entries[1:], entries[0])
	}
}

func TestCreateCallGraphFromEntriesErrors(t *testing.T) {
	prog, f := exactEntryFixture(t)
	other, of := exactEntryFixture(t)
	_ = other
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name    string
		ctx     context.Context
		prog    *ssa.Program
		entries []*ssa.Function
	}{
		{"nil program", context.Background(), nil, []*ssa.Function{f["example/a.main"]}},
		{"empty", context.Background(), prog, nil},
		{"single nil", context.Background(), prog, []*ssa.Function{nil}},
		{"all nil", context.Background(), prog, []*ssa.Function{nil, nil}},
		{"foreign program", context.Background(), prog, []*ssa.Function{f["example/a.main"], of["example/a.main"]}},
		{"canceled", canceled, prog, []*ssa.Function{f["example/a.main"]}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, root, err := CreateCallGraphFromEntries(tc.ctx, tc.prog, tc.entries)
			if err == nil || g != nil || root != nil {
				t.Fatalf("got (%v,%v,%v), want nil graph/root and error", g, root, err)
			}
			if tc.name == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	}
}

func TestExactEntriesLeavesLegacySelectionUnchanged(t *testing.T) {
	prog, f := exactEntryFixture(t)
	entries := []*ssa.Function{f["example/a.init"], f["example/a.main"], f["example/b.main"], f["example/lib.Exported"], f["example/a.hidden"], f["closure"]}
	for i := 0; i < 2; i++ {
		g, root, err := CreateMultiRootCallGraph(prog, entries)
		if err != nil {
			t.Fatal(err)
		}
		assertExactRoot(t, g, root, []*ssa.Function{f["example/a.main"], f["example/b.main"]})
		if _, _, err := CreateCallGraphFromEntries(context.Background(), prog, entries); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := CreateMultiRootCallGraph(prog, []*ssa.Function{f["example/a.init"]}); err == nil {
		t.Fatal("legacy initializer-only selection unexpectedly changed")
	}
}
