package callgraphutil_test

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"

	"github.com/picatz/taint/callgraphutil"
	"golang.org/x/tools/go/callgraph"
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

	return packages.Load(&packages.Config{
		Mode:    loadMode,
		Context: ctx,
		Env:     os.Environ(),
		Dir:     dir,
		Tests:   false,
		ParseFile: func(fset *token.FileSet, filename string, src []byte) (*ast.File, error) {
			return parser.ParseFile(fset, filename, src, parser.SkipObjectResolution)
		},
	}, pattern)
}

func loadSSA(_ context.Context, pkgs []*packages.Package) (mainFn *ssa.Function, srcFns []*ssa.Function, err error) {
	ssaProg, ssaPkgs := ssautil.Packages(pkgs, ssa.InstantiateGenerics)
	if ssaProg == nil {
		return nil, nil, fmt.Errorf("failed to create new ssa program")
	}

	ssaProg.Build()

	for _, pkg := range ssaPkgs {
		if pkg != nil {
			pkg.Build()
		}
	}

	for i := 0; i < len(ssaPkgs); i++ {
		if ssaPkgs[i] == nil {
			ssaPkgs = append(ssaPkgs[:i], ssaPkgs[i+1:]...)
			i--
		}
	}

	mainPkgs := ssautil.MainPackages(ssaPkgs)
	if len(mainPkgs) == 0 {
		return nil, nil, fmt.Errorf("no main packages found")
	}

	mainFn, _ = mainPkgs[0].Members["main"].(*ssa.Function)
	if mainFn == nil {
		return nil, nil, fmt.Errorf("failed to find main function")
	}

	for _, pkg := range ssaPkgs {
		for _, member := range pkg.Members {
			if member.Object() == nil || member.Object().Name() == "_" {
				continue
			}

			pkgFn := pkg.Func(member.Object().Name())
			if pkgFn == nil {
				continue
			}

			var addAnons func(*ssa.Function)
			addAnons = func(f *ssa.Function) {
				srcFns = append(srcFns, f)
				for _, anon := range f.AnonFuncs {
					addAnons(anon)
				}
			}
			addAnons(pkgFn)
		}
	}

	return mainFn, srcFns, nil
}

func loadCallGraph(_ context.Context, mainFn *ssa.Function, srcFns []*ssa.Function) (*callgraph.Graph, error) {
	cg, err := callgraphutil.NewGraph(mainFn, srcFns...)
	if err != nil {
		return nil, fmt.Errorf("failed to create new callgraph: %w", err)
	}
	return cg, nil
}
