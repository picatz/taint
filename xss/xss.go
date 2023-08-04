package xss

import (
	"fmt"
	"strings"

	"github.com/picatz/taint"
	"github.com/picatz/taint/callgraph"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
)

var userControlledValues = taint.NewSources(
	"*net/http.Request",
)

var injectableFunctions = taint.NewSinks(
	// Note: at this time, they *must* be a function or method.
	"(net/http.ResponseWriter).Write",
	"(net/http.ResponseWriter).WriteHeader",
)

// Analyzer finds potential XSS issues.
var Analyzer = &analysis.Analyzer{
	Name:     "xss",
	Doc:      "finds potential XSS issues",
	Run:      run,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

// imports returns true if the package imports any of the given packages.
func imports(pass *analysis.Pass, pkgs ...string) bool {
	var imported bool
	for _, imp := range pass.Pkg.Imports() {
		for _, pkg := range pkgs {
			if strings.HasSuffix(imp.Path(), pkg) {
				imported = true
				break
			}
		}
		if imported {
			break
		}
	}
	return imported
}

func run(pass *analysis.Pass) (interface{}, error) {
	// Require the log package is imported in the
	// program being analyzed before running the analysis.
	//
	// This prevents wasting time analyzing programs that don't log.
	if !imports(pass, "net/http") {
		return nil, nil
	}

	// Get the built SSA IR.
	buildSSA := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)

	// Identify the main function from the package's SSA IR.
	mainFn := buildSSA.Pkg.Func("main")
	if mainFn == nil {
		return nil, nil
	}

	// Construct a callgraph, using the main function as the root,
	// constructed of all other functions. This returns a callgraph
	// we can use to identify directed paths to logging functions.
	cg, err := callgraph.New(mainFn, buildSSA.SrcFuncs...)
	if err != nil {
		return nil, fmt.Errorf("failed to create new callgraph: %w", err)
	}

	fmt.Println(cg.String())

	// Run taint check for user controlled values (sources) ending
	// up in injectable log functions (sinks).
	results := taint.Check(cg, userControlledValues, injectableFunctions)

	// For each result, check if a prepared statement is providing
	// a mitigation for the user controlled value.
	//
	// TODO: ensure this makes sense for all the GORM usage?
	for _, result := range results {
		pass.Reportf(result.SinkValue.Pos(), "potential log injection")
	}

	return nil, nil
}
