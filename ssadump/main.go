package main

import (
	"fmt"
	"os"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func main() {
	patterns := os.Args[1:]

	var allNeeds = packages.NeedName |
		packages.NeedFiles |
		packages.NeedCompiledGoFiles |
		packages.NeedImports |
		packages.NeedTypes |
		packages.NeedTypesSizes |
		packages.NeedSyntax |
		packages.NeedTypesInfo |
		packages.NeedDeps

	var cfg = &packages.Config{
		Mode: allNeeds,
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
