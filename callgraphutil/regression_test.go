package callgraphutil

import (
	"context"
	"fmt"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

func TestPathsSearchFindsDistinctPaths(t *testing.T) {
	prog := ssa.NewProgram(token.NewFileSet(), ssa.InstantiateGenerics)
	sig := types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false)

	root := prog.NewFunction("root", sig, "test")
	left := prog.NewFunction("left", sig, "test")
	right := prog.NewFunction("right", sig, "test")
	target := prog.NewFunction("target", sig, "test")

	g := &callgraph.Graph{Nodes: make(map[*ssa.Function]*callgraph.Node)}
	g.Root = g.CreateNode(root)
	callgraph.AddEdge(g.CreateNode(root), nil, g.CreateNode(left))
	callgraph.AddEdge(g.CreateNode(root), nil, g.CreateNode(right))
	callgraph.AddEdge(g.CreateNode(left), nil, g.CreateNode(target))
	callgraph.AddEdge(g.CreateNode(right), nil, g.CreateNode(target))

	paths := PathsSearch(g.Root, func(n *callgraph.Node) bool {
		return n != nil && n.Func == target
	})
	if len(paths) != 2 {
		t.Fatalf("expected 2 distinct paths to target, got %d", len(paths))
	}
}

func TestDeduplicateEdgesKeepsInOutConsistent(t *testing.T) {
	prog := ssa.NewProgram(token.NewFileSet(), ssa.InstantiateGenerics)
	sig := types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false)

	root := prog.NewFunction("root", sig, "test")
	target := prog.NewFunction("target", sig, "test")

	g := &callgraph.Graph{Nodes: make(map[*ssa.Function]*callgraph.Node)}
	g.Root = g.CreateNode(root)
	callgraph.AddEdge(g.CreateNode(root), nil, g.CreateNode(target))
	callgraph.AddEdge(g.CreateNode(root), nil, g.CreateNode(target))

	DeduplicateEdges(g)

	rootNode := g.CreateNode(root)
	targetNode := g.CreateNode(target)
	if len(rootNode.Out) != 1 {
		t.Fatalf("expected one outgoing edge after dedupe, got %d", len(rootNode.Out))
	}
	if len(targetNode.In) != 1 {
		t.Fatalf("expected one incoming edge after dedupe, got %d", len(targetNode.In))
	}
	if targetNode.In[0] != rootNode.Out[0] {
		t.Fatal("incoming edge does not match outgoing edge")
	}
}

func TestNewGraphRejectsNilRoot(t *testing.T) {
	if _, err := NewGraph(nil); err == nil {
		t.Fatal("expected nil root error")
	}
}

func TestPathSearchHandlesNilStart(t *testing.T) {
	if path := PathSearch(nil, func(*callgraph.Node) bool { return true }); path != nil {
		t.Fatalf("expected nil path for nil start, got %v", path)
	}
	if path := PathSearchCallTo(nil, "target"); path != nil {
		t.Fatalf("expected nil call path for nil start, got %v", path)
	}
}

func TestInterfaceInvokeUsesConcreteImplementation(t *testing.T) {
	cg, pkgPath := graphForSource(t, `package main

type runner interface{ Run() }
type impl struct{}

func (impl) Run() { target() }
func target() {}

func main() {
	var r runner = impl{}
	r.Run()
}
`)

	if paths := PathsSearchCallTo(cg.Root, pkgPath+".target"); len(paths) == 0 {
		t.Fatal("expected path to concrete target through interface invoke")
	}
	for fn := range cg.Nodes {
		if fn != nil && fn.String() == "Run" {
			t.Fatalf("unexpected package/name-only synthetic method node: %s", fn)
		}
	}
}

func TestFunctionFieldResolutionUsesMatchingAllocation(t *testing.T) {
	cg, pkgPath := graphForSource(t, `package main

type runner struct{ run func() }

func first() {}
func second() {}

func main() {
	a := runner{run: first}
	b := runner{run: second}
	_ = a
	b.run()
}
`)

	if paths := PathsSearchCallTo(cg.Root, pkgPath+".second"); len(paths) == 0 {
		t.Fatal("expected path to function stored in called field")
	}
	if paths := PathsSearchCallTo(cg.Root, pkgPath+".first"); len(paths) != 0 {
		t.Fatalf("did not expect path to function stored in different struct instance, got %d", len(paths))
	}
}

func TestInstructionsForSearchesMatchedNode(t *testing.T) {
	cg, pkgPath := graphForSource(t, `package main

func target() {}

func helper() {
	target()
}

func main() {
	helper()
}
`)

	var call *ssa.Call
	for fn := range cg.Nodes {
		if fn == nil || fn.String() != pkgPath+".helper" {
			continue
		}
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				if c, ok := instr.(*ssa.Call); ok {
					call = c
				}
			}
		}
	}
	if call == nil {
		t.Fatal("failed to find helper call instruction")
	}
	instr := InstructionsFor(cg.Root, call)
	if instr == nil {
		t.Fatal("expected instruction to be found outside root function")
	}
	if instr.Pos() != call.Pos() {
		t.Fatal("found instruction position does not match target value")
	}
}

// TestCallgraphEdgeOrderingIsCanonical asserts that NewGraph leaves every
// node's Out slice ordered by the canonical key (site position, then
// callee identity). The construction algorithm walks `map[*ssa.Function]bool`
// values in random order; without explicit canonicalization the edge order
// in Out changes between consecutive runs. Verifying the post-condition
// here catches regressions in Canonicalize itself or new construction
// paths that forget to call it.
func TestCallgraphEdgeOrderingIsCanonical(t *testing.T) {
	cg, _ := graphForSource(t, `package main

func a() {}
func b() {}
func c() {}

func main() {
	a()
	b()
	c()
	a()
	c()
	b()
}
`)
	for _, node := range cg.Nodes {
		if node == nil {
			continue
		}
		assertEdgesCanonical(t, "Out", node.Out)
		assertEdgesCanonical(t, "In", node.In)
	}
}

// TestCallgraphIsDeterministicAcrossBuilds builds the same source twice
// using independent ssa.Programs and asserts the resulting callgraph
// matches edge-for-edge when keyed by stable function identity and source
// position. Direct token.Pos values are not comparable across programs
// (each has its own FileSet), so the comparison uses (callee.String(),
// fset.Position(site.Pos()) line+col).
func TestCallgraphIsDeterministicAcrossBuilds(t *testing.T) {
	src := `package main

type sink struct{}

func (sink) one() {}
func (sink) two() {}

func helperA(s sink) { s.one() }
func helperB(s sink) { s.two() }

func main() {
	s := sink{}
	helperA(s)
	helperB(s)
	helperA(s)
}
`
	a := buildCanonicalFingerprint(t, src)
	b := buildCanonicalFingerprint(t, src)
	if a != b {
		t.Fatalf("callgraph fingerprint changed across runs\nrun A:\n%s\nrun B:\n%s", a, b)
	}
}

func TestGlobalFunctionDispatchUsesReachingStore(t *testing.T) {
	cg, pkgPath := graphForSource(t, `package main

var dispatch func(string)

func source() string { return "user" }
func safe(string) {}
func unsafe(string) {}

func main() {
	dispatch = safe
	dispatch(source())
	dispatch = unsafe
}
`)

	if paths := PathsSearchCallTo(cg.Root, pkgPath+".safe"); len(paths) == 0 {
		t.Fatal("expected dispatch to call reaching safe function")
	}
	if paths := PathsSearchCallTo(cg.Root, pkgPath+".unsafe"); len(paths) != 0 {
		t.Fatalf("did not expect later global function store to create unsafe edge, got %d paths", len(paths))
	}
}

func TestGlobalFunctionDispatchUsesPriorUnsafeStore(t *testing.T) {
	cg, pkgPath := graphForSource(t, `package main

var dispatch func(string)

func source() string { return "user" }
func unsafe(string) {}

func main() {
	dispatch = unsafe
	dispatch(source())
}
`)

	if paths := PathsSearchCallTo(cg.Root, pkgPath+".unsafe"); len(paths) == 0 {
		t.Fatal("expected dispatch to call prior unsafe function")
	}
}

func TestMapFunctionDispatchFiltersConstantKey(t *testing.T) {
	cg, pkgPath := graphForSource(t, `package main

var handlers = map[string]func(string){
	"safe": safe,
	"unsafe": unsafe,
}

func source() string { return "user" }
func safe(string) {}
func unsafe(string) {}

func main() {
	handlers["safe"](source())
}
`)

	if paths := PathsSearchCallTo(cg.Root, pkgPath+".safe"); len(paths) == 0 {
		t.Fatal("expected constant safe key to call safe handler")
	}
	if paths := PathsSearchCallTo(cg.Root, pkgPath+".unsafe"); len(paths) != 0 {
		t.Fatalf("did not expect constant safe key to call unsafe handler, got %d paths", len(paths))
	}
}

func TestMapFunctionDispatchUnknownKeyStaysConservative(t *testing.T) {
	cg, pkgPath := graphForSource(t, `package main

var handlers = map[string]func(string){
	"safe": safe,
	"unsafe": unsafe,
}

func source() string { return "user" }
func key() string { return "safe" }
func safe(string) {}
func unsafe(string) {}

func main() {
	handlers[key()](source())
}
`)

	if paths := PathsSearchCallTo(cg.Root, pkgPath+".safe"); len(paths) == 0 {
		t.Fatal("expected unknown key to conservatively call safe handler")
	}
	if paths := PathsSearchCallTo(cg.Root, pkgPath+".unsafe"); len(paths) == 0 {
		t.Fatal("expected unknown key to conservatively call unsafe handler")
	}
}

// assertEdgesCanonical fails the test if edges is not sorted by edgeCompare.
func assertEdgesCanonical(t *testing.T, label string, edges []*callgraph.Edge) {
	t.Helper()
	for i := 1; i < len(edges); i++ {
		if edgeCompare(edges[i], edges[i-1]) < 0 {
			t.Fatalf("%s edges out of canonical order at index %d: %s !< %s",
				label, i, edgeDebug(edges[i-1]), edgeDebug(edges[i]))
		}
	}
}

func edgeDebug(e *callgraph.Edge) string {
	if e == nil {
		return "<nil>"
	}
	pos := token.NoPos
	if e.Site != nil {
		pos = e.Site.Pos()
	}
	callee := ""
	if e.Callee != nil && e.Callee.Func != nil {
		callee = e.Callee.Func.String()
	}
	return callee + "@" + posString(pos)
}

func posString(p token.Pos) string {
	if !p.IsValid() {
		return "novalid"
	}
	return "valid"
}

// buildCanonicalFingerprint constructs a callgraph from src and serializes
// its edges into a string keyed on stable identifiers. The fset.Position is
// used so the fingerprint is portable across separate ssa.Program builds
// of the same source. Temp-dir filenames are rewritten to "main.go" so
// fingerprints compare equal across t.TempDir() invocations.
func buildCanonicalFingerprint(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/determinism\n\ngo 1.24.4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := loadPackages(context.Background(), dir, "./...")
	if err != nil {
		t.Fatal(err)
	}
	mainFn, srcFns, err := loadSSA(context.Background(), pkgs)
	if err != nil {
		t.Fatal(err)
	}
	cg, err := NewGraph(mainFn, srcFns...)
	if err != nil {
		t.Fatal(err)
	}
	fset := mainFn.Prog.Fset
	var buf []byte
	nodes := SortedNodes(cg)
	for _, n := range nodes {
		buf = append(buf, "node "...)
		buf = append(buf, nodeKey(n)...)
		buf = append(buf, '\n')
		for _, e := range n.Out {
			buf = append(buf, "  -> "...)
			buf = append(buf, calleeKey(e)...)
			if e.Site != nil {
				p := fset.Position(e.Site.Pos())
				buf = append(buf, " @ main.go:"...)
				buf = append(buf, []byte(fmt.Sprintf("%d:%d", p.Line, p.Column))...)
			}
			buf = append(buf, '\n')
		}
	}
	return string(buf)
}

func graphForSource(t *testing.T, src string) (*callgraph.Graph, string) {
	t.Helper()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/regression\n\ngo 1.24.4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	pkgs, err := loadPackages(context.Background(), dir, "./...")
	if err != nil {
		t.Fatal(err)
	}
	mainFn, srcFns, err := loadSSA(context.Background(), pkgs)
	if err != nil {
		t.Fatal(err)
	}
	cg, err := NewGraph(mainFn, srcFns...)
	if err != nil {
		t.Fatal(err)
	}
	return cg, mainFn.Pkg.Pkg.Path()
}
