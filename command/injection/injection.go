package injection

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

var injectableCommandFunctions = taint.NewSinks(
	"os/exec.Command",
	"os/exec.CommandContext",
)

var supportedCommandPackages = []string{
	"os/exec",
}

// Analyzer finds potential command injection issues.
var Analyzer = &analysis.Analyzer{
	Name:     "cmdi",
	Doc:      "finds potential command injection issues",
	Run:      run,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

var debugCmdI bool
var callGraphAlgorithm = string(callgraphutil.CallGraphAlgorithmTaint)

var models modelflag.Flag

func init() {
	fs := flag.NewFlagSet("cmdi", flag.ContinueOnError)
	fs.BoolVar(&debugCmdI, "debug", false, "enable debug logging for command injection analyzer")
	fs.StringVar(&callGraphAlgorithm, "callgraph", callGraphAlgorithm, "callgraph algorithm: taint or vta")
	models.Register(fs)
	Analyzer.Flags = *fs
	if os.Getenv("CMDI_DEBUG") != "" {
		debugCmdI = true
	}
}

func dbg(format string, args ...any) {
	if debugCmdI {
		fmt.Fprintf(os.Stderr, "[cmdi-debug] "+format+"\n", args...)
	}
}

// imports returns true if the package imports any of the given packages.
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
	gate := supportedCommandPackages
	if len(loadedModels) > 0 {
		gate = append(slices.Clone(supportedCommandPackages), taint.ModelPackages(loadedModels)...)
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

	diagnostics := taint.CheckDetailed(cg, userControlledValues, injectableCommandFunctions, taint.WithModels(loadedModels...))
	dbg("results=%d", len(diagnostics))

	for _, diagnostic := range diagnostics {
		result := diagnostic.Result
		if debugCmdI {
			dbg("path=%s", callgraphutil.Path(result.Path).String())
			for _, evidence := range diagnostic.Evidence {
				dbg("evidence=%s rule=%s msg=%s", evidence.Kind, evidence.Rule, evidence.Message)
			}
		}
		reportPos := resultPosition(result)
		if !reportPos.IsValid() {
			continue
		}
		pass.Reportf(reportPos, "potential command injection")
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
