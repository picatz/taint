// Package ssrf implements an analyzer that detects potential server-side
// request forgery (CWE-918) vulnerabilities: user-controlled values reaching
// outbound HTTP or network APIs in a position that controls the destination
// (URL or address).
package ssrf

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
	"golang.org/x/tools/go/callgraph"
)

// builtinModelsFS holds the detector's built-in rules as data: the sources,
// the outbound-request sinks with their URL-argument selectors, and the
// packages that gate the analysis.
//
//go:embed models
var builtinModelsFS embed.FS

var builtinModels = mustLoadBuiltinModels()

func mustLoadBuiltinModels() []taint.Model {
	sub, err := fs.Sub(builtinModelsFS, "models")
	if err != nil {
		panic(fmt.Errorf("ssrf: %w", err))
	}
	ms, err := taint.LoadModels(sub)
	if err != nil {
		panic(fmt.Errorf("ssrf: loading built-in models: %w", err))
	}
	return ms
}

// Analyzer finds potential server-side request forgery issues.
var Analyzer = &analysis.Analyzer{
	Name:     "ssrf",
	Doc:      "finds potential server-side request forgery issues",
	Run:      run,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

var debugSSRF bool
var callGraphAlgorithm = string(callgraphutil.CallGraphAlgorithmTaint)

var models modelflag.Flag

func init() {
	fs := flag.NewFlagSet("ssrf", flag.ContinueOnError)
	fs.BoolVar(&debugSSRF, "debug", false, "enable debug logging for ssrf analyzer")
	fs.StringVar(&callGraphAlgorithm, "callgraph", callGraphAlgorithm, "callgraph algorithm: taint or vta")
	models.Register(fs)
	Analyzer.Flags = *fs
	if os.Getenv("SSRF_DEBUG") != "" {
		debugSSRF = true
	}
}

func dbg(format string, args ...any) {
	if debugSSRF {
		fmt.Fprintf(os.Stderr, "[ssrf-debug] "+format+"\n", args...)
	}
}

func run(pass *analysis.Pass) (any, error) {
	userModels, err := models.Load()
	if err != nil {
		return nil, err
	}
	allModels := append(slices.Clone(builtinModels), userModels...)
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

	// A go/analysis pass carries no context; whole-program callers pass a
	// real one through Check for cancelation.
	for _, f := range checkGraph(context.Background(), cg, allModels) {
		pass.Reportf(f.Pos, "%s", f.Message)
	}

	return nil, nil
}

// Check runs the SSRF detector over an already-built call graph and returns the
// located findings. The per-package Analyzer and a whole-program driver share
// it, so a flow that crosses a package boundary, invisible to the per-package
// pass, is reported identically when the driver supplies a whole-program graph.
// Canceling ctx stops the check early, bounding the per-sink path enumeration.
func Check(ctx context.Context, cg *callgraph.Graph) []taint.Finding {
	userModels, err := models.Load()
	if err != nil {
		return nil
	}
	allModels := append(slices.Clone(builtinModels), userModels...)
	return checkGraph(ctx, cg, allModels)
}

func checkGraph(ctx context.Context, cg *callgraph.Graph, allModels []taint.Model) []taint.Finding {
	diagnostics := taint.CheckDetailed(cg, taint.NewSources(), taint.NewSinks(), taint.WithModels(allModels...), taint.WithContext(ctx))
	dbg("results=%d", len(diagnostics))
	return diagnostics.Findings("potential server-side request forgery")
}
