// Package ssrf implements an analyzer that detects potential server-side
// request forgery (CWE-918) vulnerabilities: user-controlled values reaching
// outbound HTTP or network APIs in a position that controls the destination
// (URL or address).
package ssrf

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

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
)

var userControlledValues = taint.NewSources(
	"*net/http.Request",
	"google.golang.org/protobuf/proto.Message",
)

var injectableNetworkFunctions = taint.NewSinks(
	"net/http.Get",
	"net/http.Post",
	"net/http.PostForm",
	"net/http.Head",
	"net/http.NewRequest",
	"net/http.NewRequestWithContext",
	"(*net/http.Client).Do",
	"(*net/http.Client).Get",
	"(*net/http.Client).Post",
	"(*net/http.Client).PostForm",
	"(*net/http.Client).Head",
	"net.Dial",
	"net.DialTimeout",
)

// Packages whose presence is required before this analyzer attempts the
// expensive call-graph walk; programs that import neither net/http nor net
// cannot meaningfully reach a SSRF sink.
var supportedNetworkPackages = []string{
	"net/http",
	"net",
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

func init() {
	fs := flag.NewFlagSet("ssrf", flag.ContinueOnError)
	fs.BoolVar(&debugSSRF, "debug", false, "enable debug logging for ssrf analyzer")
	fs.StringVar(&callGraphAlgorithm, "callgraph", callGraphAlgorithm, "callgraph algorithm: taint or vta")
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
	if !imports(pass, supportedNetworkPackages...) {
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

	diagnostics := taint.CheckDetailed(cg, userControlledValues, injectableNetworkFunctions)
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
