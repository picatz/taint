package injection

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"slices"

	"github.com/picatz/taint"
	"github.com/picatz/taint/callgraphutil"
	"github.com/picatz/taint/internal/modelflag"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
)

// builtinModelsFS holds the detector's built-in rules as data: the sources,
// the logging-call sinks (every call is a sink with default all-argument
// selection), and the packages that gate the analysis.
//
//go:embed models
var builtinModelsFS embed.FS

var builtinModels = mustLoadBuiltinModels()

func mustLoadBuiltinModels() []taint.Model {
	sub, err := fs.Sub(builtinModelsFS, "models")
	if err != nil {
		panic(fmt.Errorf("logi: %w", err))
	}
	ms, err := taint.LoadModels(sub)
	if err != nil {
		panic(fmt.Errorf("logi: loading built-in models: %w", err))
	}
	return ms
}

// Analyzer finds potential log injection issues to demonstrate
// the github.com/picatz/taint package.
var Analyzer = &analysis.Analyzer{
	Name:     "logi",
	Doc:      "finds potential log injection issues",
	Run:      run,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

var debugLogI bool
var callGraphAlgorithm = string(callgraphutil.CallGraphAlgorithmTaint)

var models modelflag.Flag

func init() {
	fs := flag.NewFlagSet("logi", flag.ContinueOnError)
	fs.BoolVar(&debugLogI, "debug", false, "enable debug logging for log injection analyzer")
	fs.StringVar(&callGraphAlgorithm, "callgraph", callGraphAlgorithm, "callgraph algorithm: taint or vta")
	models.Register(fs)
	Analyzer.Flags = *fs
	if os.Getenv("LOGI_DEBUG") != "" {
		debugLogI = true
	}
}

func dbg(format string, args ...any) {
	if debugLogI {
		fmt.Fprintf(os.Stderr, "[logi-debug] "+format+"\n", args...)
	}
}

func run(pass *analysis.Pass) (any, error) {
	// Require the log package is imported in the
	// program being analyzed before running the analysis.
	//
	// This prevents wasting time analyzing programs that don't log.
	userModels, err := models.Load()
	if err != nil {
		return nil, err
	}
	allModels := append(slices.Clone(builtinModels), userModels...)
	if !taint.ImportsAny(pass.Pkg, taint.ModelPackages(allModels)...) {
		return nil, nil
	}

	// Get the built SSA IR.
	buildSSA := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)

	// Identify the main function from the package's SSA IR.
	mainFn := buildSSA.Pkg.Func("main")

	// Construct a callgraph, using the main function as the root,
	// constructed of all other functions. This returns a callgraph
	// we can use to identify directed paths to logging functions.
	cg, _, err := callgraphutil.BuildCallGraph(
		context.Background(),
		callgraphutil.CallGraphAlgorithm(callGraphAlgorithm),
		buildSSA.Pkg.Prog,
		mainFn,
		buildSSA.SrcFuncs,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create callgraph: %w", err)
	}

	// Run taint check for user controlled values (sources) ending
	// up in injectable log functions (sinks).
	diagnostics := taint.CheckDetailed(cg, taint.NewSources(), taint.NewSinks(), taint.WithModels(allModels...))
	dbg("results=%d", len(diagnostics))

	// Report each tainted log call discovered at the concrete callsite if available.
	for _, diagnostic := range diagnostics {
		result := diagnostic.Result
		if debugLogI {
			dbg("path=%s", callgraphutil.Path(result.Path).String())
			for _, evidence := range diagnostic.Evidence {
				dbg("evidence=%s rule=%s msg=%s", evidence.Kind, evidence.Rule, evidence.Message)
			}
		}
		reportPos := result.ReportPos()
		if !reportPos.IsValid() {
			continue
		}
		pass.Reportf(reportPos, "potential log injection")
	}

	return nil, nil
}
