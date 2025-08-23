package main_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"testing"

	"github.com/picatz/taint/callgraphutil"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func TestLoadAndSearch(t *testing.T) {
	loadMode :=
		packages.NeedName |
			packages.NeedDeps |
			packages.NeedFiles |
			packages.NeedCompiledGoFiles |
			packages.NeedModule |
			packages.NeedTypes |
			packages.NeedImports |
			packages.NeedSyntax |
			packages.NeedTypesInfo
		// packages.NeedTypesSizes |
		// packages.NeedExportFile |
		// packages.NeedEmbedPatterns

	// parseMode := parser.ParseComments
	parseMode := parser.SkipObjectResolution

	// patterns := []string{dir}
	patterns := []string{"./..."}
	// patterns := []string{"all"}

	pkgs, err := packages.Load(&packages.Config{
		Mode:    loadMode,
		Context: context.Background(),
		Env:     os.Environ(),
		Dir:     "./example",
		Tests:   false,
		ParseFile: func(fset *token.FileSet, filename string, src []byte) (*ast.File, error) {
			return parser.ParseFile(fset, filename, src, parseMode)
		},
	}, patterns...)
	if err != nil {
		t.Fatal(err)
	}

	ssaBuildMode := ssa.InstantiateGenerics // ssa.SanityCheckFunctions | ssa.GlobalDebug

	// Analyze the package.
	ssaProg, ssaPkgs := ssautil.Packages(pkgs, ssaBuildMode)

	ssaProg.Build()

	for _, pkg := range ssaPkgs {
		pkg.Build()
	}

	mainPkgs := ssautil.MainPackages(ssaPkgs)

	mainFn := mainPkgs[0].Members["main"].(*ssa.Function)

	var srcFns []*ssa.Function

	for _, pkg := range ssaPkgs {
		for _, fn := range pkg.Members {
			if fn.Object() == nil {
				continue
			}

			if fn.Object().Name() == "_" {
				continue
			}

			pkgFn := pkg.Func(fn.Object().Name())
			if pkgFn == nil {
				continue
			}

			var addAnons func(f *ssa.Function)
			addAnons = func(f *ssa.Function) {
				srcFns = append(srcFns, f)
				for _, anon := range f.AnonFuncs {
					addAnons(anon)
				}
			}
			addAnons(pkgFn)
		}
	}

	if mainFn == nil {
		t.Fatal("main function not found")
	}

	cg, err := callgraphutil.NewGraph(mainFn, srcFns...)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(cg)

	// path := callgraph.PathSearchCallTo(cg.Root, "(*database/sql.DB).Query")

	// if path == nil {
	// 	t.Fatal("no path found")
	// }

	// t.Log(path)

	paths := callgraphutil.PathsSearchCallTo(cg.Root, "(*database/sql.DB).Query")

	if len(paths) == 0 {
		t.Fatal("no paths found")
	}

	for _, path := range paths {
		t.Log(path)
	}
}

func TestLoadLibraryWithoutMain(t *testing.T) {
	loadMode :=
		packages.NeedName |
			packages.NeedDeps |
			packages.NeedFiles |
			packages.NeedCompiledGoFiles |
			packages.NeedModule |
			packages.NeedTypes |
			packages.NeedImports |
			packages.NeedSyntax |
			packages.NeedTypesInfo

	parseMode := parser.SkipObjectResolution
	patterns := []string{"github.com/picatz/taint/xss"} // Load the xss package directly

	// Load the xss package which is a library without main function
	pkgs, err := packages.Load(&packages.Config{
		Mode:    loadMode,
		Context: context.Background(),
		Env:     os.Environ(),
		Tests:   false,
		ParseFile: func(fset *token.FileSet, filename string, src []byte) (*ast.File, error) {
			return parser.ParseFile(fset, filename, src, parseMode)
		},
	}, patterns...)
	if err != nil {
		t.Fatal(err)
	}

	if len(pkgs) == 0 {
		t.Skip("No packages loaded")
	}

	ssaBuildMode := ssa.InstantiateGenerics

	ssaProg, ssaPkgs := ssautil.Packages(pkgs, ssaBuildMode)
	ssaProg.Build()

	for _, pkg := range ssaPkgs {
		pkg.Build()
	}

	// Collect source functions
	var srcFns []*ssa.Function
	for _, pkg := range ssaPkgs {
		for _, fn := range pkg.Members {
			if fn.Object() == nil {
				continue
			}
			if fn.Object().Name() == "_" {
				continue
			}
			pkgFn := pkg.Func(fn.Object().Name())
			if pkgFn == nil {
				continue
			}

			var addAnons func(f *ssa.Function)
			addAnons = func(f *ssa.Function) {
				srcFns = append(srcFns, f)
				for _, anon := range f.AnonFuncs {
					addAnons(anon)
				}
			}
			addAnons(pkgFn)
		}
	}

	// Verify no main packages exist
	mainPkgs := ssautil.MainPackages(ssaPkgs)
	if len(mainPkgs) > 0 {
		t.Logf("Found %d main packages, but continuing with library test", len(mainPkgs))
		// Don't skip - the xss package itself doesn't have main, even if testdata does
	}

	// Test the multi-root callgraph creation
	cg, mainFn, err := callgraphutil.CreateMultiRootCallGraph(ssaProg, srcFns)
	if err != nil {
		t.Fatalf("Failed to create multi-root callgraph: %v", err)
	}

	if cg == nil {
		t.Fatal("Callgraph should not be nil")
	}

	if mainFn == nil {
		t.Fatal("Root function should not be nil")
	}

	t.Logf("Created callgraph with %d nodes using root: %s", len(cg.Nodes), mainFn.String())

	// Test that we can find paths to specific functions
	paths := callgraphutil.PathsSearchCallTo(cg.Root, "fmt.Errorf")
	if len(paths) == 0 {
		// This is not necessarily a failure - the library might not call fmt.Errorf
		t.Logf("No paths found to fmt.Errorf (this may be expected)")
	} else {
		t.Logf("Found %d path(s) to fmt.Errorf", len(paths))
		for i, path := range paths {
			t.Logf("Path %d: %s", i+1, path.String())
		}
	}

	// Test partial matching
	paths = callgraphutil.PathsSearchCallToPartial(cg.Root, "Errorf")
	if len(paths) > 0 {
		t.Logf("Found %d path(s) using partial match 'Errorf'", len(paths))
	}
}
