package injection

import (
    "fmt"
    "go/types"
    "strings"
    "flag"
    "os"

	"github.com/picatz/taint"
	"github.com/picatz/taint/callgraphutil"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
)

var userControlledValues = taint.NewSources(
	"*net/http.Request",
	"google.golang.org/protobuf/proto.Message",
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

	// github.com/golang/glog
	"github.com/golang/glog.Infof",
	"github.com/golang/glog.Infoln",
	"github.com/golang/glog.Info",
	"github.com/golang/glog.Warningf",
	"github.com/golang/glog.Warningln",
	"github.com/golang/glog.Warning",
	"github.com/golang/glog.Errorf",
	"github.com/golang/glog.Errorln",
	"github.com/golang/glog.Error",
	"github.com/golang/glog.Fatalf",
	"github.com/golang/glog.Fatalln",
	"github.com/golang/glog.Fatal",

	// github.com/golang/glog.Verbose methods for V-style logging
	"(github.com/golang/glog.Verbose).Info",
	"(github.com/golang/glog.Verbose).Infoln",
	"(github.com/golang/glog.Verbose).Infof",
	"(github.com/golang/glog.Verbose).InfoDepth",
	"(github.com/golang/glog.Verbose).InfoDepthf",
	"(github.com/golang/glog.Verbose).InfoContext",
	"(github.com/golang/glog.Verbose).InfoContextf",
	"(github.com/golang/glog.Verbose).InfoContextDepth",
	"(github.com/golang/glog.Verbose).InfoContextDepthf",

	// github.com/hashicorp/go-hclog
	"(*github.com/hashicorp/go-hclog.Logger).Trace",
	"(*github.com/hashicorp/go-hclog.Logger).Debug",
	"(*github.com/hashicorp/go-hclog.Logger).Info",
	"(*github.com/hashicorp/go-hclog.Logger).Warn",
	"(*github.com/hashicorp/go-hclog.Logger).Error",
	"(*github.com/hashicorp/go-hclog.Logger).Named",

	// github.com/sirupsen/logrus
	"github.com/sirupsen/logrus.Debug",
	"github.com/sirupsen/logrus.Info",
	"github.com/sirupsen/logrus.Warn",
	"github.com/sirupsen/logrus.Error",
	"github.com/sirupsen/logrus.Fatal",
	"github.com/sirupsen/logrus.Panic",
	"(*github.com/sirupsen/logrus.Logger).Debug",
	"(*github.com/sirupsen/logrus.Logger).Info",
	"(*github.com/sirupsen/logrus.Logger).Warn",
	"(*github.com/sirupsen/logrus.Logger).Error",
	"(*github.com/sirupsen/logrus.Logger).Fatal",
	"(*github.com/sirupsen/logrus.Logger).Panic",

	// go.uber.org/zap
	"(*go.uber.org/zap.Logger).Debug",
	"(*go.uber.org/zap.Logger).Info",
	"(*go.uber.org/zap.Logger).Warn",
	"(*go.uber.org/zap.Logger).Error",
	"(*go.uber.org/zap.Logger).DPanic",
	"(*go.uber.org/zap.Logger).Panic",
	"(*go.uber.org/zap.Logger).Fatal",
	"(*go.uber.org/zap.SugaredLogger).Debug",
	"(*go.uber.org/zap.SugaredLogger).Info",
	"(*go.uber.org/zap.SugaredLogger).Warn",
	"(*go.uber.org/zap.SugaredLogger).Error",
	"(*go.uber.org/zap.SugaredLogger).DPanic",
	"(*go.uber.org/zap.SugaredLogger).Panic",
	"(*go.uber.org/zap.SugaredLogger).Fatal",

// TODO: support configuring additional logging packages here as needed.
)

var supportedLogPackages = []string{
	"log",
	"log/slog",
	"github.com/golang/glog",
	"github.com/hashicorp/go-hclog",
	"github.com/sirupsen/logrus",
	"go.uber.org/zap",
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

func init() {
    fs := flag.NewFlagSet("logi", flag.ContinueOnError)
    fs.BoolVar(&debugLogI, "debug", false, "enable debug logging for log injection analyzer")
    Analyzer.Flags = *fs
    if os.Getenv("LOGI_DEBUG") != "" {
        debugLogI = true
    }
}

func dbg(format string, args ...interface{}) {
    if debugLogI {
        fmt.Fprintf(os.Stderr, "[logi-debug] "+format+"\n", args...)
    }
}

// imports returns true if the package imports any of the given packages.
func imports(pass *analysis.Pass, pkgs ...string) bool {
	visited := make(map[*types.Package]bool)
	var walk func(*types.Package) bool
	walk = func(p *types.Package) bool {
		if visited[p] {
			return false
		}
		visited[p] = true
		for _, pkg := range pkgs {
			if p.Path() == pkg || strings.HasPrefix(p.Path(), pkg+"/") {
				return true
			}
		}
		for _, imp := range p.Imports() {
			if walk(imp) {
				return true
			}
		}
		return false
	}
	return walk(pass.Pkg)
}

func run(pass *analysis.Pass) (any, error) {
	// Require the log package is imported in the
	// program being analyzed before running the analysis.
	//
	// This prevents wasting time analyzing programs that don't log.
	if !imports(pass, supportedLogPackages...) {
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
	cg, err := callgraphutil.NewGraph(mainFn, buildSSA.SrcFuncs...)
	if err != nil {
		return nil, fmt.Errorf("failed to create new callgraph: %w", err)
	}

    // Run taint check for user controlled values (sources) ending
    // up in injectable log functions (sinks).
    results := taint.Check(cg, userControlledValues, injectableLogFunctions)
    dbg("results=%d", len(results))

    // Report each tainted log call discovered at the concrete callsite if available.
    for _, result := range results {
        if debugLogI {
            dbg("path=%s", callgraphutil.Path(result.Path).String())
        }
        reportPos := result.SinkValue.Pos()
        if len(result.Path) > 0 {
            if last := result.Path[len(result.Path)-1]; last != nil && last.Site != nil {
                reportPos = last.Site.Pos()
            }
        }
        pass.Reportf(reportPos, "potential log injection")
    }

	return nil, nil
}
