package taint_test

import (
	"fmt"

	"github.com/picatz/taint"
	"github.com/picatz/taint/callgraphutil"
	sqlinjection "github.com/picatz/taint/sql/injection"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

func ExampleCheck() {
	var cg *callgraph.Graph

	sources := taint.NewSources("*net/http.Request")
	sinks := taint.NewSinks("(*database/sql.DB).Query")

	results := taint.Check(cg, sources, sinks)
	_ = results
}

func ExampleCheckDetailed() {
	var cg *callgraph.Graph

	sources := taint.NewSources("*net/http.Request")
	sinks := taint.NewSinks("(net/http.ResponseWriter).Write")

	diagnostics := taint.CheckDetailed(cg, sources, sinks, taint.WithSanitizers("html.EscapeString"))
	for _, diagnostic := range diagnostics {
		for _, evidence := range diagnostic.Evidence {
			fmt.Println(evidence.Kind, evidence.Message)
		}
	}
}

func Example_analyzer() {
	_ = sqlinjection.Analyzer
}

func Example_callgraphConstructionForLibraryPackages() {
	var prog *ssa.Program
	var srcFns []*ssa.Function

	cg, syntheticRoot, err := callgraphutil.CreateMultiRootCallGraph(prog, srcFns)
	_, _, _ = cg, syntheticRoot, err
}
