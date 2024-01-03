package injection

import (
	"fmt"
	"strings"

	"github.com/picatz/taint"
	"github.com/picatz/taint/callgraph"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
)

var userControlledValues = taint.NewSources(
	"*net/http.Request",
)

var injectableLogFunctions = taint.NewSinks(
	// Note: at this time, they *must* be a function or method.
	"log.Fatal",
	"log.Fatalf",
	"log.Fatalln",
	"log.Panic",
	"log.Panicf",
	"log.Panicln",
	"log.Print",
	"log.Printf",
	"log.Println",
	"log.Output",
	"log.SetOutput",
	"log.SetPrefix",
	"log.Writer",
	"(*log.Logger).Fatal",
	"(*log.Logger).Fatalf",
	"(*log.Logger).Fatalln",
	"(*log.Logger).Panic",
	"(*log.Logger).Panicf",
	"(*log.Logger).Panicln",
	"(*log.Logger).Print",
	"(*log.Logger).Printf",
	"(*log.Logger).Println",
	"(*log.Logger).Output",
	"(*log.Logger).SetOutput",
	"(*log.Logger).SetPrefix",
	"(*log.Logger).Writer",

	// log/slog (structured logging)
	// https://pkg.go.dev/log/slog
	"log/slog.Debug",
	"log/slog.DebugContext",
	"log/slog.Error",
	"log/slog.ErrorContext",
	"log/slog.Info",
	"log/slog.InfoContext",
	"log/slog.Warn",
	"log/slog.WarnContext",
	"log/slog.Log",
	"log/slog.LogAttrs",
	"(*log/slog.Logger).With",
	"(*log/slog.Logger).Debug",
	"(*log/slog.Logger).DebugContext",
	"(*log/slog.Logger).Error",
	"(*log/slog.Logger).ErrorContext",
	"(*log/slog.Logger).Info",
	"(*log/slog.Logger).InfoContext",
	"(*log/slog.Logger).Warn",
	"(*log/slog.Logger).WarnContext",
	"(*log/slog.Logger).Log",
	"(*log/slog.Logger).LogAttrs",
	"log/slog.NewRecord",
	"(*log/slog.Record).Add",
	"(*log/slog.Record).AddAttrs",

	// TODO: consider adding the following logger packages,
	//       and the ability to configure this list generically.
	//
	// https://pkg.go.dev/golang.org/x/exp/slog
	// https://pkg.go.dev/github.com/golang/glog
	// https://pkg.go.dev/github.com/hashicorp/go-hclog
	// https://pkg.go.dev/github.com/sirupsen/logrus
	// https://pkg.go.dev/go.uber.org/zap
	// ...
)

// Analyzer finds potential log injection issues to demonstrate
// the github.com/picatz/taint package.
var Analyzer = &analysis.Analyzer{
	Name:     "logi",
	Doc:      "finds potential log injection issues",
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
	if !imports(pass, "log", "log/slog") {
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

	// Run taint check for user controlled values (sources) ending
	// up in injectable log functions (sinks).
	results := taint.Check(cg, userControlledValues, injectableLogFunctions)

	// For each result, check if a prepared statement is providing
	// a mitigation for the user controlled value.
	//
	// TODO: ensure this makes sense for all the GORM usage?
	for _, result := range results {
		pass.Reportf(result.SinkValue.Pos(), "potential log injection")
	}

	return nil, nil
}
