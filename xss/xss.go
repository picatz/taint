package xss

import (
	"fmt"
	"strings"

	"github.com/picatz/taint"
	"github.com/picatz/taint/callgraph"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
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

	// fmt.Println(cg)

	// Run taint check for user controlled values (sources) ending
	// up in injectable log functions (sinks).
	results := taint.Check(cg, userControlledValues, injectableFunctions)

	for _, result := range results {
		// Check if html.EscapeString was called on the source value
		// before it was passed to the sink.
		var escaped bool
		for _, edge := range result.Path {
			for _, arg := range edge.Site.Common().Args {
				taint.WalkSSA(arg, func(v ssa.Value) error {
					call, ok := v.(*ssa.Call)
					if !ok {
						return nil
					}
					if call.Call.Value.String() == "html.EscapeString" {
						escaped = true
						return taint.ErrStopWalk
					}
					return nil
				})
			}
			if escaped {
				break
			}
		}

		if !escaped {
			pass.Reportf(result.SinkValue.Pos(), "potential XSS")
		}
	}

	return nil, nil
}

// checkIfHTMLEscapeString returns true if the given value uses
// html.EscapeString, calling itself recursively as needed.
func checkIfHTMLEscapeString(value ssa.Value) bool {
	switch value := value.(type) {
	case *ssa.Call:
		return value.Call.Value.String() == "html.EscapeString"
	case *ssa.MakeInterface:
		return checkIfHTMLEscapeString(value.X)
	case *ssa.ChangeInterface:
		return checkIfHTMLEscapeString(value.X)
	case *ssa.Convert:
		return checkIfHTMLEscapeString(value.X)
	case *ssa.UnOp:
		return checkIfHTMLEscapeString(value.X)
	case *ssa.Phi:
		for _, edge := range value.Edges {
			if checkIfHTMLEscapeString(edge) {
				return true
			}
		}
		return false
	case *ssa.Alloc:
		refs := value.Referrers()
		if refs == nil {
			return false
		}
		for _, instr := range *refs {
			for _, opr := range instr.Operands(nil) {
				if checkIfHTMLEscapeString(*opr) {
					return true
				}
			}
		}
	case *ssa.FieldAddr:
		return checkIfHTMLEscapeString(value.X)
	case *ssa.Field:
		return checkIfHTMLEscapeString(value.X)
	case *ssa.IndexAddr:
		return checkIfHTMLEscapeString(value.X)
	case *ssa.Index:
		return checkIfHTMLEscapeString(value.X)
	case *ssa.Lookup:
		return checkIfHTMLEscapeString(value.X)
	case *ssa.Slice:
		return checkIfHTMLEscapeString(value.X)
	default:
		// fmt.Printf("unknown type: %T\n", value)
	}

	return false
}
