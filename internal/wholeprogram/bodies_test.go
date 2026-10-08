package wholeprogram

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/picatz/taint"
	sqli "github.com/picatz/taint/sql/injection"
	"golang.org/x/tools/go/packages"
)

func TestBodiesConfiguration(t *testing.T) {
	for _, cfg := range []Config{
		{Bodies: "all"},
		{Bodies: BodiesSameModule, BodyLimits: BodyLimits{1, 1}},
		{Scope: ScopeSelected, Bodies: BodiesSameModule},
		{Scope: ScopeSelected, Bodies: BodiesSameModule, BodyLimits: BodyLimits{-1, 1}},
		{Scope: ScopeSelected, Bodies: BodiesSameModule, BodyLimits: BodyLimits{1, -1}},
		{BodyLimits: BodyLimits{1, 0}},
	} {
		cfg.Dir = "/does/not/exist"
		p, err := Load(context.Background(), cfg)
		if p != nil || err == nil || strings.Contains(err.Error(), "loading packages") {
			t.Fatalf("config %+v: program=%v err=%v", cfg, p, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p, err := Load(ctx, Config{})
	if p != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v %v", p, err)
	}
}

func TestBodiesSameModuleExactBudget(t *testing.T) {
	t.Setenv("GOWORK", "off")
	dir, err := filepath.Abs("testdata/bodycoverage")
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Dir: dir, Patterns: []string{"./caller"}, Scope: ScopeSelected, Bodies: BodiesSameModule, BodyLimits: BodyLimits{1, 110}}
	p, err := Load(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := p.BodyCoverage()
	if p.Bodies != BodiesSameModule || len(p.Packages) != 1 || len(p.MatchPackages) != 1 || p.MatchPackages[0] != p.Packages[0].Types || c.AdditionalSyntaxBytes != 110 || !reflect.DeepEqual(c.BuiltSameModuleDependencies, []string{"example.com/bodycoverage/helper"}) {
		t.Fatalf("expanded inputs: %+v", c)
	}
	for _, entry := range p.Entries {
		if entry.Pkg != nil && entry.Pkg.Pkg != p.Packages[0].Types {
			t.Fatalf("helper became root: %v", entry)
		}
	}
	got := sqli.CheckWithOptions(context.Background(), p.CallGraph, taint.WithMatchPackages(p.MatchPackages...))
	if len(got) != 1 {
		t.Fatalf("want unsafe-only finding, got %v", got)
	}
	cfg.BodyLimits.MaxAdditionalSyntaxBytes--
	p, err = Load(context.Background(), cfg)
	if p != nil || err == nil || !strings.Contains(err.Error(), "required 1 additional packages and 110 syntax bytes; allowed 1 packages and 109 syntax bytes") {
		t.Fatalf("under-budget: %v %v", p, err)
	}
}

// Synthetic graph tests cover malformed loader metadata and identity boundaries
// that a successful real go/packages load normally prevents.
func bodyTestPackage(t *testing.T, id string, mod *packages.Module, source string) *packages.Package {
	t.Helper()
	fs := token.NewFileSet()
	file, err := parser.ParseFile(fs, "/overlay/shared.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	return &packages.Package{ID: id, Module: mod, Fset: fs, Types: types.NewPackage(id, "p"), TypesInfo: &types.Info{}, Syntax: []*ast.File{file}, CompiledGoFiles: []string{"/overlay/shared.go"}}
}

func TestBodiesPlanningIdentityAndAccounting(t *testing.T) {
	ctx := context.Background()
	a := &packages.Module{Path: "example.com/a", Dir: "/a", GoMod: "/a/go.mod", Main: true}
	b := &packages.Module{Path: "example.com/b", Dir: "/a/nested", GoMod: "/a/nested/go.mod", Main: true}
	src := "package p\nfunc F(){}\n"
	root := bodyTestPackage(t, "a", a, src)
	helper := bodyTestPackage(t, "a/helper", a, src)
	variant := *helper
	variant.ID = "a/helper [a/helper.test]"
	variant.Types = types.NewPackage("a/helper", "p")
	sibling := bodyTestPackage(t, "b/helper", b, src)
	external := bodyTestPackage(t, "stdlib", nil, src)
	replacement := *a
	replacement.Replace = b
	replaced := bodyTestPackage(t, "replaced", &replacement, src)
	root.Imports = map[string]*packages.Package{"helper": helper, "variant": &variant, "sibling": sibling, "external": external, "replaced": replaced}
	limits := BodyLimits{2, int64(2 * len(src))}
	extra, size, err := additionalBodies(ctx, []*packages.Package{root}, limits)
	if err != nil || size != limits.MaxAdditionalSyntaxBytes || len(extra) != 2 || extra[0] != helper || extra[1] != &variant {
		t.Fatalf("accounting: %v %d %v", extra, size, err)
	}
	// The shared AST/token.File and identical filename must be charged per variant.
	for i := 0; i < 10; i++ {
		again, n, e := additionalBodies(ctx, []*packages.Package{root}, limits)
		if e != nil || n != size || !reflect.DeepEqual(extra, again) {
			t.Fatalf("non-deterministic: %v %d %v", again, n, e)
		}
	}
	for _, low := range []BodyLimits{{1, limits.MaxAdditionalSyntaxBytes}, {2, limits.MaxAdditionalSyntaxBytes - 1}} {
		extra, _, err := additionalBodies(ctx, []*packages.Package{root}, low)
		if extra != nil || err == nil || !strings.Contains(err.Error(), "required 2 additional packages") {
			t.Fatalf("budget: %v %v", extra, err)
		}
	}
	// Selecting the workspace sibling itself makes only its reachable module eligible.
	otherRoot := bodyTestPackage(t, "b", b, src)
	extra, _, err = additionalBodies(ctx, []*packages.Package{root, otherRoot}, BodyLimits{3, 1000})
	if err != nil || len(extra) != 3 || extra[2] != sibling {
		t.Fatalf("workspace selected modules: %v %v", extra, err)
	}
	// Same replacement directory cannot erase a different original module tuple.
	different := *a
	different.Path = "example.com/alias"
	different.Replace = b
	root.Imports["alias"] = bodyTestPackage(t, "alias", &different, src)
	extra, _, err = additionalBodies(ctx, []*packages.Package{root}, limits)
	if err != nil || len(extra) != 2 {
		t.Fatalf("replacement identity: %v %v", extra, err)
	}
}

func TestBodiesPlanningRejectsIncompleteGraphs(t *testing.T) {
	mod := &packages.Module{Path: "example.com/a", Dir: "/a", GoMod: "/a/go.mod"}
	for _, tc := range []struct {
		name   string
		mutate func(*packages.Package, *packages.Package)
	}{
		{"unknown selected", func(root, helper *packages.Package) { root.Module = nil }},
		{"missing types", func(root, helper *packages.Package) { helper.Types = nil }},
		{"missing type info", func(root, helper *packages.Package) { helper.TypesInfo = nil }},
		{"ill typed", func(root, helper *packages.Package) { helper.IllTyped = true }},
		{"missing syntax", func(root, helper *packages.Package) { helper.Syntax = nil }},
		{"missing compiled file", func(root, helper *packages.Package) { helper.CompiledGoFiles = nil }},
		{"missing file set", func(root, helper *packages.Package) { helper.Fset = nil }},
		{"missing token file", func(root, helper *packages.Package) { helper.Fset = token.NewFileSet() }},
		{"nil syntax", func(root, helper *packages.Package) { helper.Syntax[0] = nil }},
		{"duplicate id", func(root, helper *packages.Package) { copy := *helper; root.Imports["duplicate"] = &copy }},
		{"nil import", func(root, helper *packages.Package) { root.Imports["nil"] = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := bodyTestPackage(t, "a", mod, "package p")
			helper := bodyTestPackage(t, "a/helper", mod, "package p")
			root.Imports = map[string]*packages.Package{"helper": helper}
			tc.mutate(root, helper)
			extra, _, err := additionalBodies(context.Background(), []*packages.Package{root}, BodyLimits{10, 1000})
			if extra != nil || err == nil {
				t.Fatalf("incomplete graph accepted: %v %v", extra, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	root := bodyTestPackage(t, "a", mod, "package p")
	extra, _, err := additionalBodies(ctx, []*packages.Package{root}, BodyLimits{10, 1000})
	if extra != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled plan: %v %v", extra, err)
	}
}

func TestBodiesLoadedOverlayAndTestVariants(t *testing.T) {
	t.Setenv("GOWORK", "off")
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":                "module example.com/overlay\ngo 1.26.0\n",
		"caller/caller.go":      "package caller\nimport \"example.com/overlay/helper\"\nfunc F()string{return helper.F()}\n",
		"helper/helper.go":      "package helper\nfunc F()string{return \"disk\"}\n",
		"helper/helper_test.go": "package helper\nfunc testOnly(){}\n",
	}
	for name, src := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0600); err != nil {
			t.Fatal(err)
		}
	}
	overlay := []byte("package helper\nfunc F()string{return \"longer overlay contents than disk\"}\n")
	pkgs, err := packages.Load(&packages.Config{Mode: loadMode, Dir: dir, Overlay: map[string][]byte{filepath.Join(dir, "helper/helper.go"): overlay}}, "./caller")
	if err != nil || len(LoadErrors(pkgs)) > 0 {
		t.Fatalf("load: %v %v", err, LoadErrors(pkgs))
	}
	extra, size, err := additionalBodies(context.Background(), pkgs, BodyLimits{1, int64(len(overlay))})
	if err != nil || len(extra) != 1 || size != int64(len(overlay)) {
		t.Fatalf("overlay accounting: %v %d %v", extra, size, err)
	}
	// Real loader variants share filenames and sometimes ASTs. Supply caller as
	// the original selection and expose the additional loaded test variant graph.
	variants, err := packages.Load(&packages.Config{Mode: loadMode, Dir: dir, Tests: true}, "./helper")
	if err != nil || len(LoadErrors(variants)) > 0 {
		t.Fatalf("test load: %v %v", err, LoadErrors(variants))
	}
	var original, variant *packages.Package
	for _, pkg := range variants {
		if pkg.ID == "example.com/overlay/helper" {
			original = pkg
		}
		if strings.Contains(pkg.ID, "[example.com/overlay/helper.test]") {
			variant = pkg
		}
	}
	if original == nil || variant == nil {
		t.Fatalf("test variant absent: %v", variants)
	}
	// Use exactly this second load's identities and Fsets, never join graphs.
	root := bodyTestPackage(t, "selected", original.Module, "package p")
	root.Imports = map[string]*packages.Package{"normal": original, "variant": variant}
	want := int64(2*len(files["helper/helper.go"]) + len(files["helper/helper_test.go"]))
	extra, size, err = additionalBodies(context.Background(), []*packages.Package{root}, BodyLimits{2, want})
	if err != nil || len(extra) != 2 || size != want {
		t.Fatalf("variant accounting: %v %d want %d: %v", extra, size, want, err)
	}
}

func TestBodiesLoadedWorkspaceReplacementAndNestedModule(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"go.work":            "go 1.26.0\nuse (\n ./a\n ./b\n)\n",
		"a/go.mod":           "module example.com/a\ngo 1.26.0\nrequire (\n example.com/third v0.0.0\n example.com/nested v0.0.0\n)\nreplace example.com/third => ../third\nreplace example.com/nested => ./nested\n",
		"a/caller/caller.go": "package caller\nimport (\"example.com/a/helper\"; b \"example.com/b/helper\";\"example.com/third\";\"example.com/nested\")\nfunc F()string{return helper.F()+b.F()+third.F()+nested.F()}\n",
		"a/helper/helper.go": "package helper\nfunc F()string{return \"a\"}\n",
		"a/nested/go.mod":    "module example.com/nested\ngo 1.26.0\n",
		"a/nested/nested.go": "package nested\nfunc F()string{return \"nested\"}\n",
		"b/go.mod":           "module example.com/b\ngo 1.26.0\n",
		"b/helper/helper.go": "package helper\nfunc F()string{return \"b\"}\n",
		"third/go.mod":       "module example.com/third\ngo 1.26.0\n",
		"third/third.go":     "package third\nfunc F()string{return \"third\"}\n",
	}
	for name, src := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOWORK", filepath.Join(dir, "go.work"))
	p, err := Load(context.Background(), Config{Dir: dir, Patterns: []string{"./a/caller"}, Scope: ScopeSelected, Bodies: BodiesSameModule, BodyLimits: BodyLimits{1, int64(len(files["a/helper/helper.go"]))}})
	if err != nil {
		t.Fatal(err)
	}
	c := p.BodyCoverage()
	if !reflect.DeepEqual(c.BuiltSameModuleDependencies, []string{"example.com/a/helper"}) || c.OtherDependencies != 3 {
		t.Fatalf("module coverage: %+v", c)
	}
	for _, pkg := range p.SSA.AllPackages() {
		if pkg.Pkg.Path() == "example.com/b/helper" || pkg.Pkg.Path() == "example.com/third" || pkg.Pkg.Path() == "example.com/nested" {
			if fn := pkg.Func("F"); fn != nil && len(fn.Blocks) > 0 {
				t.Fatalf("external body built: %s", fn)
			}
		}
	}
}
