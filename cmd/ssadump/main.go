package main

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/signal"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	patterns := os.Args[1:]

	if len(patterns) == 0 {
		fmt.Fprintf(os.Stderr, "usage: %s <patterns>\n", os.Args[0])
		os.Exit(1)
	}

	loadMode := packages.NeedName |
		packages.NeedFiles |
		packages.NeedCompiledGoFiles |
		packages.NeedImports |
		packages.NeedTypes |
		packages.NeedTypesSizes |
		packages.NeedSyntax |
		packages.NeedTypesInfo |
		packages.NeedDeps

	parseMode := parser.SkipObjectResolution

	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get current working directory: %v\n", err.Error())
		os.Exit(1)
	}

	cfg := &packages.Config{
		Mode:    loadMode,
		Context: ctx,
		Dir:     dir,
		Env:     os.Environ(),
		ParseFile: func(fset *token.FileSet, filename string, src []byte) (*ast.File, error) {
			return parser.ParseFile(fset, filename, src, parseMode)
		},
	}

	initial, err := packages.Load(cfg, patterns...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err.Error())
		os.Exit(1)
	}

	// bubble up all loaded package  errors
	for _, pkg := range initial {
		if len(pkg.Errors) != 0 {
			for _, err := range pkg.Errors {
				fmt.Fprintf(os.Stderr, "%v\n", err.Error())
			}
		}
	}

	_, pkgs := ssautil.Packages(initial, 0)

	for _, pkg := range pkgs {
		// malformed packages will be nil
		if pkg != nil {
			pkg.Build()
			for _, m := range pkg.Members {
				if fn, ok := m.(*ssa.Function); ok {
					fn.WriteTo(os.Stdout)
				}
			}
		}
	}
}
