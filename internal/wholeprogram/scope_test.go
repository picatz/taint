package wholeprogram

import (
	"context"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

func selectedScopeFixture(t *testing.T) string {
	t.Helper()
	t.Setenv("GOWORK", "off")
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.com/selected\ngo 1.26.0\n",
		"dep/dep.go": `package dep
func Exported() {}
type Foreign struct{}
func (Foreign) Promoted() {}
func (*Foreign) PromotedPointer() {}
`,
		"lib/lib.go": `package lib
import "example.com/selected/dep"
var Initialized = initialize()
func initialize() int { dep.Exported(); return 1 }
func init() { initialize() }
func Exported() {}
func hidden() {}
type API struct { dep.Foreign }
type APIAlias = API
func (API) Value() {}
func (*API) Pointer() {}
func (API) hiddenMethod() {}
type hiddenType struct{}
func (hiddenType) ExportedMethod() {}
`,
		"cmd/one/main.go": `package main
import "example.com/selected/lib"
var Initialized = lib.Initialized
func init() { lib.Exported() }
func main() {}
func DeadExported() {}
`,
		"cmd/two/main.go": `package main
func main() {}
func DeadExported() {}
`,
	}
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func loadSelectedScope(t *testing.T, dir string, patterns ...string) *Program {
	t.Helper()
	p, err := Load(context.Background(), Config{Dir: dir, Patterns: patterns, Scope: ScopeSelected})
	if err != nil {
		t.Fatal(err)
	}
	if p.Scope != ScopeSelected {
		t.Fatalf("effective scope = %q", p.Scope)
	}
	if len(p.MatchPackages) != len(p.Packages) {
		t.Fatalf("matching identities = %d, loaded packages = %d", len(p.MatchPackages), len(p.Packages))
	}
	identities := make(map[*types.Package]bool)
	for _, pkg := range p.MatchPackages {
		identities[pkg] = true
	}
	for _, pkg := range p.Packages {
		if !identities[pkg.Types] {
			t.Fatalf("original package identity %s not retained", pkg.ID)
		}
	}
	return p
}

func assertSelectedRootSet(t *testing.T, p *Program, want []*ssa.Function) {
	t.Helper()
	expected := make(map[*ssa.Function]bool)
	for _, fn := range want {
		if fn == nil {
			t.Fatal("nil expected entry")
		}
		expected[fn] = true
	}
	if len(p.Entries) != len(expected) {
		t.Fatalf("entries = %v, want %d distinct functions", entryNames(p), len(expected))
	}
	for _, fn := range p.Entries {
		if !expected[fn] {
			t.Errorf("unexpected entry %s", fn)
		}
		delete(expected, fn)
	}
	if len(expected) != 0 {
		t.Fatalf("missing entries: %v", expected)
	}
	if p.CallGraph.Root == nil || p.CallGraph.Root.Func == nil || p.CallGraph.Root.Func.Synthetic == "" {
		t.Fatal("selected scope requires a synthetic graph root")
	}
	if len(p.CallGraph.Root.Out) != len(p.Entries) {
		t.Fatalf("root edges = %d, entries = %d", len(p.CallGraph.Root.Out), len(p.Entries))
	}
	for _, fn := range p.Entries {
		expected[fn] = true
	}
	for _, edge := range p.CallGraph.Root.Out {
		if !expected[edge.Callee.Func] {
			t.Errorf("unexpected or duplicate graph root edge: %s", edge.Callee.Func)
		}
		delete(expected, edge.Callee.Func)
	}
	if len(expected) != 0 {
		t.Fatalf("entries absent from exact graph root: %v", expected)
	}
}

func selectedSSAPackage(t *testing.T, p *Program, suffix string) *ssa.Package {
	t.Helper()
	for _, pkg := range p.SSA.AllPackages() {
		if pkg.Pkg.Path() == "example.com/selected/"+suffix {
			return pkg
		}
	}
	t.Fatalf("missing SSA package %s", suffix)
	return nil
}

func TestSelectedScopeLibraryAPIAndBodies(t *testing.T) {
	dir := selectedScopeFixture(t)
	p := loadSelectedScope(t, dir, "./lib")
	lib := selectedSSAPackage(t, p, "lib")
	dep := selectedSSAPackage(t, p, "dep")
	want := []*ssa.Function{lib.Func("init"), lib.Func("Exported")}
	api := lib.Type("API").Type()
	// Enumerate the public API explicitly: both value and pointer method sets,
	// including foreign promoted methods and the pointer wrapper of Value.
	for _, tc := range []struct {
		receiver types.Type
		names    []string
	}{
		{api, []string{"Value", "Promoted"}},
		{types.NewPointer(api), []string{"Value", "Pointer", "Promoted", "PromotedPointer"}},
	} {
		for _, name := range tc.names {
			selection := p.SSA.MethodSets.MethodSet(tc.receiver).Lookup(nil, name)
			if selection == nil {
				t.Fatalf("missing %s method %s", tc.receiver, name)
			}
			fn := p.SSA.MethodValue(selection)
			want = append(want, fn)
			if strings.HasPrefix(name, "Promoted") && fn.Object().Pkg() != dep.Pkg {
				t.Fatalf("promoted %s declaration ownership = %v, want original dependency", fn, fn.Object().Pkg())
			}
		}
	}
	assertSelectedRootSet(t, p, want)
	if len(lib.Func("initialize").Blocks) == 0 || !selectedScopeReachable(p, lib.Func("initialize")) {
		t.Fatal("selected package initializer's helper body must be built and reachable")
	}
	if len(dep.Func("Exported").Blocks) != 0 {
		t.Fatal("imported dependency body was expanded")
	}
	foreign := dep.Type("Foreign").Type()
	for _, tc := range []struct {
		receiver types.Type
		name     string
	}{{foreign, "Promoted"}, {types.NewPointer(foreign), "PromotedPointer"}} {
		fn := p.SSA.MethodValue(p.SSA.MethodSets.MethodSet(tc.receiver).Lookup(nil, tc.name))
		if len(fn.Blocks) != 0 {
			t.Fatalf("imported method declaration %s has a body", fn)
		}
	}
	c := p.BodyCoverage()
	if !reflect.DeepEqual(c.SelectedPackages, []string{"example.com/selected/lib"}) || !reflect.DeepEqual(c.SameModuleDependencies, []string{"example.com/selected/dep"}) {
		t.Fatalf("selected body coverage changed: %+v", c)
	}
	// A fresh load must select the same ordered roots despite map iteration.
	again := loadSelectedScope(t, dir, "./lib")
	if !reflect.DeepEqual(entryNames(p), entryNames(again)) {
		t.Fatalf("entry order is unstable: %v versus %v", entryNames(p), entryNames(again))
	}
}

func TestSelectedScopeMainRootsWin(t *testing.T) {
	dir := selectedScopeFixture(t)
	for _, tc := range []struct {
		name            string
		patterns, mains []string
	}{
		{"single command includes initializer", []string{"./cmd/one"}, []string{"cmd/one"}},
		{"multiple commands", []string{"./cmd/two", "./cmd/one"}, []string{"cmd/one", "cmd/two"}},
		{"main and library", []string{"./lib", "./cmd/one"}, []string{"cmd/one"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := loadSelectedScope(t, dir, tc.patterns...)
			var want []*ssa.Function
			for _, name := range tc.mains {
				pkg := selectedSSAPackage(t, p, name)
				want = append(want, pkg.Func("main"), pkg.Func("init"))
			}
			assertSelectedRootSet(t, p, want)
			main := selectedSSAPackage(t, p, "cmd/one")
			if !selectedScopeReachable(p, main.Func("init#1")) {
				t.Fatal("explicit initializer is not reachable from exact entries")
			}
		})
	}
}

func TestScopeLegacyDefaultAndInvalid(t *testing.T) {
	dir := selectedScopeFixture(t)
	var entries [][]string
	for _, scope := range []Scope{"", ScopeLegacy} {
		p, err := Load(context.Background(), Config{Dir: dir, Patterns: []string{"./lib"}, Scope: scope})
		if err != nil {
			t.Fatal(err)
		}
		if p.Scope != ScopeLegacy {
			t.Fatalf("effective scope = %q, want legacy", p.Scope)
		}
		if p.MatchPackages != nil {
			t.Fatal("legacy matching scope must remain unrestricted (nil)")
		}
		names := entryNames(p)
		sort.Strings(names)
		entries = append(entries, names)
	}
	if !reflect.DeepEqual(entries[0], entries[1]) {
		t.Fatalf("zero scope and explicit legacy roots differ: %v", entries)
	}
	// An invalid scope must be rejected even when loading would fail first.
	_, err := Load(context.Background(), Config{Dir: filepath.Join(dir, "does-not-exist"), Scope: Scope("invalid-profile")})
	if err == nil || !strings.Contains(err.Error(), "scope") || !strings.Contains(err.Error(), "invalid-profile") || strings.Contains(err.Error(), "loading packages") {
		t.Fatalf("invalid scope was not rejected before loading: %v", err)
	}
}

func selectedScopeReachable(p *Program, fn *ssa.Function) bool {
	seen := make(map[*callgraph.Node]bool)
	var visit func(*callgraph.Node) bool
	visit = func(node *callgraph.Node) bool {
		if node == nil || seen[node] {
			return false
		}
		seen[node] = true
		if node.Func == fn {
			return true
		}
		for _, edge := range node.Out {
			if visit(edge.Callee) {
				return true
			}
		}
		return false
	}
	return fn != nil && visit(p.CallGraph.Root)
}
