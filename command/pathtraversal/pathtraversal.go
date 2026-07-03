// Package pathtraversal implements an analyzer that detects potential
// path-traversal (CWE-22) vulnerabilities: user-controlled values reaching
// filesystem APIs that open, read, write, or remove files keyed by path.
package pathtraversal

import (
	"context"
	"flag"
	"fmt"
	"go/token"
	"go/types"
	"os"
	"slices"
	"strings"

	"github.com/picatz/taint"
	"github.com/picatz/taint/callgraphutil"
	"github.com/picatz/taint/internal/modelflag"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
)

var userControlledValues = taint.NewSources(
	"*net/http.Request",
	"google.golang.org/protobuf/proto.Message",
)

var injectableFileFunctions = taint.NewSinks(
	"os.Open",
	"os.OpenFile",
	"os.Create",
	"os.ReadFile",
	"os.WriteFile",
	"os.Remove",
	"os.RemoveAll",
	"os.Mkdir",
	"os.MkdirAll",
	"io/ioutil.ReadFile",
	"io/ioutil.WriteFile",
	"io/ioutil.ReadDir",
	"net/http.ServeFile",
)

// Trigger packages whose presence indicates the program performs filesystem
// I/O that this analyzer could meaningfully inspect. We avoid running on
// programs that obviously cannot trip a sink.
var supportedFilePackages = []string{
	"os",
	"io/ioutil",
	"net/http",
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
	loadedModels, err := models.Load()
	if err != nil {
		return nil, err
	}
	gate := supportedFilePackages
	if len(loadedModels) > 0 {
		gate = append(slices.Clone(supportedFilePackages), taint.ModelPackages(loadedModels)...)
	}
	if !imports(pass, gate...) {
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

	diagnostics := taint.CheckDetailed(cg, userControlledValues, injectableFileFunctions, taint.WithModels(loadedModels...))
	dbg("results=%d", len(diagnostics))

	for _, diagnostic := range diagnostics {
		result := diagnostic.Result
		if debugPtrv {
			dbg("path=%s", callgraphutil.Path(result.Path).String())
			for _, evidence := range diagnostic.Evidence {
				dbg("evidence=%s rule=%s msg=%s", evidence.Kind, evidence.Rule, evidence.Message)
			}
		}
		reportPos := resultPosition(result)
		if !reportPos.IsValid() {
			continue
		}
		pass.Reportf(reportPos, "potential path traversal")
	}

	return nil, nil
}

func resultPosition(result taint.Result) token.Pos {
	if len(result.Path) > 0 {
		if last := result.Path.Last(); last != nil && last.Site != nil {
			return last.Site.Pos()
		}
	}
	if result.SinkValue != nil {
		return result.SinkValue.Pos()
	}
	return token.NoPos
}
