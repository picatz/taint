// Package pathtraversal implements an analyzer that detects potential
// path-traversal (CWE-22) vulnerabilities: user-controlled values reaching
// filesystem APIs that open, read, write, or remove files keyed by path.
package pathtraversal

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

// builtinModelsFS holds the detector's built-in rules as data. The sources,
// sinks (with their path-argument selectors), and the packages that gate the
// analysis are all derived from this pack rather than hardcoded in Go.
//
//go:embed models
var builtinModelsFS embed.FS

var builtinModels = mustLoadBuiltinModels()

func mustLoadBuiltinModels() []taint.Model {
	sub, err := fs.Sub(builtinModelsFS, "models")
	if err != nil {
		panic(fmt.Errorf("ptrv: %w", err))
	}
	ms, err := taint.LoadModels(sub)
	if err != nil {
		panic(fmt.Errorf("ptrv: loading built-in models: %w", err))
	}
	return ms
}

// Analyzer finds potential path traversal issues.
var Analyzer = &analysis.Analyzer{
	Name:     "ptrv",
	Doc:      "finds potential path traversal issues",
	Run:      run,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

var debugPtrv bool
var callGraphAlgorithm = string(callgraphutil.CallGraphAlgorithmTaint)

var models modelflag.Flag

func init() {
	fs := flag.NewFlagSet("ptrv", flag.ContinueOnError)
	fs.BoolVar(&debugPtrv, "debug", false, "enable debug logging for path traversal analyzer")
	fs.StringVar(&callGraphAlgorithm, "callgraph", callGraphAlgorithm, "callgraph algorithm: taint or vta")
	models.Register(fs)
	Analyzer.Flags = *fs
	if os.Getenv("PTRV_DEBUG") != "" {
		debugPtrv = true
	}
}

func dbg(format string, args ...any) {
	if debugPtrv {
		fmt.Fprintf(os.Stderr, "[ptrv-debug] "+format+"\n", args...)
	}
}

func run(pass *analysis.Pass) (any, error) {
	userModels, err := models.Load()
	if err != nil {
		return nil, err
	}
	allModels := append(slices.Clone(builtinModels), userModels...)
	// Gate on the packages named by the models (the built-in file packages
	// plus any the user added), so we skip programs that cannot trip a sink.
	if !taint.ImportsAny(pass.Pkg, taint.ModelPackages(allModels)...) {
		return nil, nil
	}

	buildSSA := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)
	mainFn := buildSSA.Pkg.Func("main")

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

	diagnostics := taint.CheckDetailed(cg, taint.NewSources(), taint.NewSinks(), taint.WithModels(allModels...))
	dbg("results=%d", len(diagnostics))

	for _, diagnostic := range diagnostics {
		result := diagnostic.Result
		if debugPtrv {
			dbg("path=%s", callgraphutil.Path(result.Path).String())
			for _, evidence := range diagnostic.Evidence {
				dbg("evidence=%s rule=%s msg=%s", evidence.Kind, evidence.Rule, evidence.Message)
			}
		}
		reportPos := result.ReportPos()
		if !reportPos.IsValid() {
			continue
		}
		pass.Reportf(reportPos, "potential path traversal")
	}

	return nil, nil
}
