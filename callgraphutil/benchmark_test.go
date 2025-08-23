package callgraphutil

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func loadPackages(ctx context.Context, dir, pattern string) ([]*packages.Package, error) {
	loadMode :=
		packages.NeedName |
			packages.NeedDeps |
			packages.NeedFiles |
			packages.NeedModule |
			packages.NeedTypes |
			packages.NeedImports |
			packages.NeedSyntax |
			packages.NeedTypesInfo

	parseMode := parser.SkipObjectResolution

	patterns := []string{pattern}

	pkgs, err := packages.Load(&packages.Config{
		Mode:    loadMode,
		Context: ctx,
		Env:     os.Environ(),
		Dir:     dir,
		Tests:   false,
		ParseFile: func(fset *token.FileSet, filename string, src []byte) (*ast.File, error) {
			return parser.ParseFile(fset, filename, src, parseMode)
		},
	}, patterns...)
	if err != nil {
		return nil, err
	}

	return pkgs, nil
}

func loadSSA(ctx context.Context, pkgs []*packages.Package) (mainFn *ssa.Function, srcFns []*ssa.Function, err error) {
	ssaBuildMode := ssa.InstantiateGenerics

	ssaProg, ssaPkgs := ssautil.Packages(pkgs, ssaBuildMode)

	if ssaProg == nil {
		err = fmt.Errorf("failed to create new ssa program")
		return
	}

	ssaProg.Build()

	for _, pkg := range ssaPkgs {
		if pkg == nil {
			continue
		}
		pkg.Build()
	}

	// Remove nil ssaPkgs
	for i := 0; i < len(ssaPkgs); i++ {
		if ssaPkgs[i] == nil {
			ssaPkgs = append(ssaPkgs[:i], ssaPkgs[i+1:]...)
			i--
		}
	}

	mainPkgs := ssautil.MainPackages(ssaPkgs)
	if len(mainPkgs) == 0 {
		err = fmt.Errorf("no main packages found")
		return
	}

	mainFn = mainPkgs[0].Members["main"].(*ssa.Function)

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
		err = fmt.Errorf("failed to find main function")
		return
	}

	return
}

func BenchmarkNewGraph(b *testing.B) {
	dir, err := filepath.Abs(filepath.Join("testdata"))
	if err != nil {
		b.Fatal(err)
	}

	pkgs, err := loadPackages(context.Background(), dir, "./...")
	if err != nil {
		b.Fatal(err)
	}

	mainFn, srcFns, err := loadSSA(context.Background(), pkgs)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportMetric(float64(len(srcFns)), "source_functions")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		graph, err := NewGraph(mainFn, srcFns...)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportMetric(float64(len(graph.Nodes)), "graph_nodes")
	}
}
