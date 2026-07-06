package injection

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"go/types"
	"io/fs"
	"slices"
	"strings"

	"github.com/picatz/taint"
	"github.com/picatz/taint/callgraphutil"
	"github.com/picatz/taint/internal/modelflag"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// builtinModelsFS holds the detector's built-in rules as data: the sources and
// the SQL query/exec sinks. Selection defaults to the engine's built-in
// selector for each method (e.g. the SQL text after a context argument for the
// pgx and GoFrame methods). The import gate stays an explicit list below
// because it includes driver packages (go-sqlite3) that host no sinks.
//
//go:embed models
var builtinModelsFS embed.FS

var builtinModels = mustLoadBuiltinModels()

func mustLoadBuiltinModels() []taint.Model {
	sub, err := fs.Sub(builtinModelsFS, "models")
	if err != nil {
		panic(fmt.Errorf("sqli: %w", err))
	}
	ms, err := taint.LoadModels(sub)
	if err != nil {
		panic(fmt.Errorf("sqli: loading built-in models: %w", err))
	}
	return ms
}

// Analyzer finds potential SQL injection issues to demonstrate
// the github.com/picatz/taint package.
var Analyzer = &analysis.Analyzer{
	Name:     "sqli",
	Doc:      "finds potential SQL injection issues",
	Run:      run,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

var callGraphAlgorithm = string(callgraphutil.CallGraphAlgorithmTaint)

var models modelflag.Flag

func init() {
	fs := flag.NewFlagSet("sqli", flag.ContinueOnError)
	fs.StringVar(&callGraphAlgorithm, "callgraph", callGraphAlgorithm, "callgraph algorithm: taint or vta")
	models.Register(fs)
	Analyzer.Flags = *fs
}

var supportedSQLPackages = []string{
	"database/sql",
	"github.com/mattn/go-sqlite3",
	"github.com/jinzhu/gorm",
	"gorm.io/gorm",
	"github.com/go-gorm/gorm",
	"github.com/jmoiron/sqlx",
	"xorm.io/xorm",
	"github.com/go-xorm/xorm",
	"github.com/go-pg/pg",
	"github.com/rqlite/gorqlite",
	"github.com/raindog308/gorqlite",
	"github.com/Masterminds/squirrel",
	"gopkg.in/Masterminds/squirrel.v1",
	"github.com/lann/squirrel",
	"github.com/jackc/pgx/v5",
	"github.com/jackc/pgx/v5/pgxpool",
	"github.com/beego/beego/v2/client/orm",
	"github.com/gogf/gf/v2/database/gdb",
}

func run(pass *analysis.Pass) (any, error) {
	// Require at least one supported SQL package to be imported before
	// running the analysis. This avoids wasting time analyzing programs
	// that do not use SQL.
	userModels, err := models.Load()
	if err != nil {
		return nil, err
	}
	// The gate stays an explicit list: it includes driver packages such as
	// go-sqlite3 that host no sinks but signal SQL usage.
	gate := append(slices.Clone(supportedSQLPackages), taint.ModelPackages(userModels)...)
	if !taint.ImportsAny(pass.Pkg, gate...) {
		return nil, nil
	}
	allModels := append(slices.Clone(builtinModels), userModels...)

	// Get the built SSA IR.
	buildSSA := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)

	// Identify the main function from the package's SSA IR.
	mainFn := buildSSA.Pkg.Func("main")

	// Construct a callgraph, using the main function as the root,
	// constructed of all other functions. This returns a callgraph
	// we can use to identify directed paths to SQL queries.
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

	// If you'd like to compare the callgraph constructed by the
	// callgraphutil package to the one constructed by others
	// (e.g. pointer analysis, rta, cha, static, etc), uncomment the
	// following lines and compare the output.
	//
	// Today, I believe the callgraphutil package is the most
	// accurate, but I'd love to be proven wrong.

	// Note: this actually panics for testcase b
	// ptares, err := pointer.Analyze(&pointer.Config{
	// 	Mains:          []*ssa.Package{buildSSA.Pkg},
	// 	BuildCallGraph: true,
	// })
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to create new callgraph using pointer analysis: %w", err)
	// }
	// cg := ptares.CallGraph

	// cg := rta.Analyze([]*ssa.Function{mainFn}, true).CallGraph
	// cg := cha.CallGraph(buildSSA.Pkg.Prog)
	// cg := static.CallGraph(buildSSA.Pkg.Prog)

	// https://github.com/golang/vuln/blob/7335627909c99e391cf911fcd214badcb8aa6d7d/internal/vulncheck/utils.go#L61
	// cg, err := callgraphutil.NewVulncheckCallGraph(context.Background(), buildSSA.Pkg.Prog, buildSSA.SrcFuncs)
	// if err != nil {
	// 	return nil, err
	// }
	// cg.Root = cg.CreateNode(mainFn)

	// fmt.Println(callgraphutil.CallGraphString(cg))

	// A go/analysis pass carries no context; whole-program callers pass a
	// real one through Check for cancelation.
	for _, f := range checkGraph(context.Background(), cg, allModels) {
		pass.Reportf(f.Pos, "%s", f.Message)
	}

	return nil, nil
}

// Check runs the SQL-injection detector over an already-built call graph and
// returns the located findings. The per-package Analyzer and a whole-program
// driver share it, so a cross-package flow (a request handler in one package
// reaching a query in another), invisible to the per-package pass, is reported
// identically when the driver supplies a whole-program graph. Canceling ctx
// stops the check early, bounding the per-sink path enumeration.
func Check(ctx context.Context, cg *callgraph.Graph) []taint.Finding {
	userModels, err := models.Load()
	if err != nil {
		return nil
	}
	allModels := append(slices.Clone(builtinModels), userModels...)
	return checkGraph(ctx, cg, allModels)
}

// checkGraph runs the taint check with the given models and applies the
// constant-query suppression, returning the findings to report.
func checkGraph(ctx context.Context, cg *callgraph.Graph, allModels []taint.Model) []taint.Finding {
	// Run taint check for user controlled values (sources) ending
	// up in injectable SQL methods (sinks).
	diagnostics := taint.CheckDetailed(cg, taint.NewSources(), taint.NewSinks(), taint.WithModels(allModels...), taint.WithContext(ctx))

	// For each result, check if a prepared statement is providing
	// a mitigation for the user controlled value.
	var findings []taint.Finding
	for _, diagnostic := range diagnostics {
		result := diagnostic.Result
		// We found a query edge that is tainted by user input, is it
		// doing this safely? We expect this to be safely done by
		// providing a prepared statement as a constant in the query
		// (first argument after context).
		queryEdge := result.Path[len(result.Path)-1]

		// Get the query arguments. For an ordinary (non-invoke) method call
		// the receiver is passed as the first argument and must be skipped;
		// for an interface invoke the receiver is carried separately (in
		// CallCommon.Value), so Args already starts at the first real
		// parameter and must not be trimmed — trimming it there would drop
		// the query text of a no-context method such as (orm.DML).Raw.
		common := queryEdge.Site.Common()
		queryArgs := common.Args
		if !common.IsInvoke() && common.Signature() != nil && common.Signature().Recv() != nil {
			if len(queryArgs) < 1 {
				continue
			}
			queryArgs = queryArgs[1:]
		}

		// Skip the context argument, if using a *Context query variant.
		//
		// This constant-query suppression is a second layer for the
		// default-selected sinks (database/sql and friends), where
		// CheckDetailed considers every argument and this check clears the
		// safe case of a constant query text with tainted bound parameters.
		// Positionally-selected sinks such as pgx (see sqlContextQueryArgument
		// in rules.go) are already precise upstream, so they are not relied
		// on here; note this heuristic assumes the SQL text is the first
		// argument after the context, which is not true for Prepare-style
		// (ctx, name, sql) signatures.
		if strings.HasSuffix(edgeCalleeName(queryEdge), "Context") {
			if len(queryArgs) < 2 {
				continue
			}
			queryArgs = queryArgs[1:]
		}

		if len(queryArgs) == 0 {
			continue
		}

		// Get the query function parameter.
		query := queryArgs[0]

		// A constant query text (prepared statement) with only bound
		// parameters after it is safe. But suppress on that basis only when
		// no later string-typed argument could be the real SQL channel: a
		// Prepare-style (ctx, name, sql) signature has a constant name first
		// and the tainted SQL after it, and must still be reported.
		if _, isConst := query.(*ssa.Const); isConst && !hasNonConstantStringArg(queryArgs[1:]) {
			continue
		}
		reportPos := result.ReportPos()
		if !reportPos.IsValid() {
			continue
		}
		findings = append(findings, taint.Finding{Pos: reportPos, Message: "potential sql injection"})
	}

	return findings
}

// hasNonConstantStringArg reports whether any argument is string-typed and not
// a constant: a candidate SQL text channel that the constant-query suppression
// must not clear. Bound parameters are variadic ...any and never trip this.
func hasNonConstantStringArg(args []ssa.Value) bool {
	for _, arg := range args {
		if arg == nil {
			continue
		}
		basic, ok := arg.Type().Underlying().(*types.Basic)
		if !ok || basic.Info()&types.IsString == 0 {
			continue
		}
		if _, isConst := arg.(*ssa.Const); !isConst {
			return true
		}
	}
	return false
}

func edgeCalleeName(edge *callgraph.Edge) string {
	if edge == nil {
		return ""
	}
	if edge.Callee != nil && edge.Callee.Func != nil {
		return edge.Callee.Func.String()
	}
	if edge.Site != nil && edge.Site.Common() != nil {
		if fn := edge.Site.Common().StaticCallee(); fn != nil {
			return fn.String()
		}
	}
	return ""
}
