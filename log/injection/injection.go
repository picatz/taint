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
	// glog Depth variants (caller-depth-adjusted logging).
	"github.com/golang/glog.InfoDepth",
	"github.com/golang/glog.InfoDepthf",
	"github.com/golang/glog.WarningDepth",
	"github.com/golang/glog.WarningDepthf",
	"github.com/golang/glog.ErrorDepth",
	"github.com/golang/glog.ErrorDepthf",
	"github.com/golang/glog.FatalDepth",
	"github.com/golang/glog.FatalDepthf",
	// glog Context variants (context-aware logging).
	"github.com/golang/glog.InfoContext",
	"github.com/golang/glog.InfoContextf",
	"github.com/golang/glog.InfoContextDepth",
	"github.com/golang/glog.InfoContextDepthf",
	"github.com/golang/glog.WarningContext",
	"github.com/golang/glog.WarningContextf",
	"github.com/golang/glog.WarningContextDepth",
	"github.com/golang/glog.WarningContextDepthf",
	"github.com/golang/glog.ErrorContext",
	"github.com/golang/glog.ErrorContextf",
	"github.com/golang/glog.ErrorContextDepth",
	"github.com/golang/glog.ErrorContextDepthf",
	"github.com/golang/glog.FatalContext",
	"github.com/golang/glog.FatalContextf",
	"github.com/golang/glog.FatalContextDepth",
	"github.com/golang/glog.FatalContextDepthf",
	// glog Exit family (logs args, then exits).
	"github.com/golang/glog.Exit",
	"github.com/golang/glog.Exitf",
	"github.com/golang/glog.Exitln",
	"github.com/golang/glog.ExitDepth",
	"github.com/golang/glog.ExitDepthf",
	"github.com/golang/glog.ExitContext",
	"github.com/golang/glog.ExitContextf",
	"github.com/golang/glog.ExitContextDepth",
	"github.com/golang/glog.ExitContextDepthf",

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

	// github.com/rs/zerolog: the terminal Msg/Msgf on an *Event carry the
	// log message, which is the injection channel.
	"(*github.com/rs/zerolog.Event).Msg",
	"(*github.com/rs/zerolog.Event).Msgf",

	// github.com/go-logr/logr: Logger is a value type, so its methods have
	// value receivers (no pointer in the qualified name).
	"(github.com/go-logr/logr.Logger).Info",
	"(github.com/go-logr/logr.Logger).Error",

	// k8s.io/klog/v2: package-level logging functions.
	"k8s.io/klog/v2.Info",
	"k8s.io/klog/v2.Infof",
	"k8s.io/klog/v2.Infoln",
	"k8s.io/klog/v2.InfoS",
	"k8s.io/klog/v2.Warning",
	"k8s.io/klog/v2.Warningf",
	"k8s.io/klog/v2.Warningln",
	"k8s.io/klog/v2.Error",
	"k8s.io/klog/v2.Errorf",
	"k8s.io/klog/v2.Errorln",
	"k8s.io/klog/v2.ErrorS",
	"k8s.io/klog/v2.Fatal",
	"k8s.io/klog/v2.Fatalf",
	"k8s.io/klog/v2.Fatalln",

	// github.com/go-kit/log: structured logging via a single Log method
	// taking alternating key/value pairs.
	"(github.com/go-kit/log.Logger).Log",

// TODO: support configuring additional logging packages here as needed.
)

var supportedLogPackages = []string{
	"log",
	"log/slog",
	"github.com/golang/glog",
	"github.com/hashicorp/go-hclog",
	"github.com/sirupsen/logrus",
	"go.uber.org/zap",
	"github.com/rs/zerolog",
	"github.com/go-logr/logr",
	"k8s.io/klog/v2",
	"github.com/go-kit/log",
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
		return slices.ContainsFunc(p.Imports(), walk)
	}
	return walk(pass.Pkg)
}

func run(pass *analysis.Pass) (any, error) {
	// Require the log package is imported in the
	// program being analyzed before running the analysis.
	//
	// This prevents wasting time analyzing programs that don't log.
	loadedModels, err := models.Load()
	if err != nil {
		return nil, err
	}
	gate := supportedLogPackages
	if len(loadedModels) > 0 {
		gate = append(slices.Clone(supportedLogPackages), taint.ModelPackages(loadedModels)...)
	}
	if !imports(pass, gate...) {
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
	diagnostics := taint.CheckDetailed(cg, userControlledValues, injectableLogFunctions, taint.WithModels(loadedModels...))
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
		reportPos := resultPosition(result)
		if !reportPos.IsValid() {
			continue
		}
		pass.Reportf(reportPos, "potential log injection")
	}

	return nil, nil
}

func resultPosition(result taint.Result) token.Pos {
	if len(result.Path) > 0 {
		if last := result.Path[len(result.Path)-1]; last != nil && last.Site != nil {
			return last.Site.Pos()
		}
	}
	if result.SinkValue != nil {
		return result.SinkValue.Pos()
	}
	return token.NoPos
}
