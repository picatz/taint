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
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"slices"
	"strings"

	"github.com/picatz/taint"
	"github.com/picatz/taint/callgraphutil"
	"github.com/picatz/taint/internal/modelflag"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
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

func imports(pass *analysis.Pass, pkgs ...string) bool {
	visited := make(map[*types.Package]bool)
	var walk func(*types.Package) bool
	walk = func(p *types.Package) bool {
		if p == nil || visited[p] {
			return false
		}
		visited[p] = true
		for _, pkg := range pkgs {
			if p.Path() == pkg || strings.HasPrefix(p.Path(), pkg+"/") {
				return true
			}
		}
		return slices.ContainsFunc(p.Imports(), walk)
	}
	return walk(pass.Pkg)
}

func run(pass *analysis.Pass) (any, error) {
	userModels, err := models.Load()
	if err != nil {
		return nil, err
	}
	allModels := append(slices.Clone(builtinModels), userModels...)
	if !imports(pass, taint.ModelPackages(allModels)...) {
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
		if debugSSRF {
			dbg("path=%s", callgraphutil.Path(result.Path).String())
			for _, evidence := range diagnostic.Evidence {
				dbg("evidence=%s rule=%s msg=%s", evidence.Kind, evidence.Rule, evidence.Message)
			}
		}
		reportPos := resultPosition(result)
		if !reportPos.IsValid() {
			continue
		}
		pass.Reportf(reportPos, "potential server-side request forgery")
	}

	return nil, nil
}

func resultPosition(result taint.Result) token.Pos {
	for i := len(result.Path) - 1; i >= 0; i-- {
		edge := result.Path[i]
		if edge == nil || edge.Site == nil {
			continue
		}
		if pos := edge.Site.Pos(); pos.IsValid() {
			return pos
		}
	}
	if result.SinkValue != nil {
		return result.SinkValue.Pos()
	}
	return token.NoPos
}
