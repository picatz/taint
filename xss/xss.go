package xss

import (
	"fmt"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/picatz/taint"
	"github.com/picatz/taint/callgraphutil"
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

func run(pass *analysis.Pass) (any, error) {
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
	cg, err := callgraphutil.NewGraph(mainFn, buildSSA.SrcFuncs...)
	if err != nil {
		return nil, fmt.Errorf("failed to create new callgraph: %w", err)
	}

	// fmt.Println(cg)

	// Run taint check for user controlled values (sources) ending
	// up in injectable log functions (sinks).
	results := taint.Check(cg, userControlledValues, injectableFunctions)

	for _, result := range results {
		// Check if html.EscapeString was called along this specific path
		escaped := false

		reportPos := result.SinkValue.Pos()
		if len(result.Path) > 0 {
			lastEdge := result.Path[len(result.Path)-1]
			if lastEdge.Site != nil {
				reportPos = lastEdge.Site.Pos()
			}
		}

		// Find the function that's directly called at the report position
		var targetFunction *ssa.Function
		for _, edge := range result.Path {
			if edge.Site != nil && edge.Site.Pos() == reportPos {
				targetFunction = edge.Callee.Func
				break
			}
		}

		if targetFunction != nil {
			// Check the target function for html.EscapeString
			for _, block := range targetFunction.Blocks {
				for _, instr := range block.Instrs {
					if call, ok := instr.(*ssa.Call); ok {
						if call.Call.Value != nil &&
							call.Call.Value.String() == "html.EscapeString" {
							escaped = true
							break
						}
					}
				}
				if escaped {
					break
				}
			}

			// If target function doesn't have escape and it's a standard library function,
			// also check the calling function (where the call site is located)
			if !escaped && (strings.Contains(targetFunction.String(), "net/http") ||
				strings.Contains(targetFunction.String(), "io.Writer")) {
				// Find the function that contains the call site
				for _, edge := range result.Path {
					if edge.Site != nil && edge.Site.Pos() == reportPos && edge.Caller != nil {
						callerFunc := edge.Caller.Func
						if callerFunc != nil {
							for _, block := range callerFunc.Blocks {
								for _, instr := range block.Instrs {
									if call, ok := instr.(*ssa.Call); ok {
										if call.Call.Value != nil &&
											call.Call.Value.String() == "html.EscapeString" {
											escaped = true
											break
										}
									}
								}
								if escaped {
									break
								}
							}
						}
						break
					}
				}
			}
		} else {
			// No specific target function found (e.g., direct call within same function)
			// Check all functions in the path for html.EscapeString
			for _, edge := range result.Path {
				if edge.Callee.Func != nil {
					for _, block := range edge.Callee.Func.Blocks {
						for _, instr := range block.Instrs {
							if call, ok := instr.(*ssa.Call); ok {
								if call.Call.Value != nil &&
									call.Call.Value.String() == "html.EscapeString" {
									escaped = true
									break
								}
							}
						}
						if escaped {
							break
						}
					}
				}
				if escaped {
					break
				}
			}
		}

		if !escaped {
			pass.Reportf(reportPos, "potential XSS")
		}
	}

	return nil, nil
}
