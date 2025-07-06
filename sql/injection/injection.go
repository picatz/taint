package injection

import (
	"fmt"
	"go/types"
	"strings"

	"github.com/picatz/taint"
	"github.com/picatz/taint/callgraphutil"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

// userControlledValues are the sources of user controlled values that
// can be tained and end up in a SQL query.
var userControlledValues = taint.NewSources(
	// Function (and method) calls that are user controlled
	// over the netork. These are all taken into account as
	// part of *net/http.Request, but are listed here for
	// demonstration purposes.
	//
	// "(net/url.Values).Get",
	// "(*net/url.URL).Query",
	// "(*net/url.URL).Redacted",
	// "(*net/url.URL).EscapedFragment",
	// "(*net/url.Userinfo).Username",
	// "(*net/url.Userinfo).Password",
	// "(*net/url.Userinfo).String",
	// "(*net/http.Request).FormFile",
	// "(*net/http.Request).FormValue",
	// "(*net/http.Request).PostFormValue",
	// "(*net/http.Request).Referer",
	// "(*net/http.Request).UserAgent",
	// "(*net/http.Request).GetBody",
	// "(net/http.Header).Get",
	// "(net/http.Header).Values",
	//
	// Types (and fields)
	"*net/http.Request",
	//
	// "google.golang.org/grpc/metadata.MD", ?
	//
	// TODO: add more, consider pointer variants and specific fields on types
	// TODO: consider support for protobuf defined *Request types...
	// TODO: consider support for gRPC request metadata (HTTP2 headers)
	// TODO: consider support for msgpack-rpc?
)

var injectableSQLMethods = taint.NewSinks(
	// Note: at this time, they *must* be a function or method.
	"(*database/sql.DB).Query",
	"(*database/sql.DB).QueryContext",
	"(*database/sql.DB).QueryRow",
	"(*database/sql.DB).QueryRowContext",
	"(*database/sql.Tx).Query",
	"(*database/sql.Tx).QueryContext",
	"(*database/sql.Tx).QueryRow",
	"(*database/sql.Tx).QueryRowContext",
	// GORM v1
	// https://gorm.io/docs/security.html
	// https://gorm.io/docs/security.html#SQL-injection-Methods
	"(*github.com/jinzhu/gorm.DB).Where",
	"(*github.com/jinzhu/gorm.DB).Or",
	"(*github.com/jinzhu/gorm.DB).Not",
	"(*github.com/jinzhu/gorm.DB).Group",
	"(*github.com/jinzhu/gorm.DB).Having",
	"(*github.com/jinzhu/gorm.DB).Joins",
	"(*github.com/jinzhu/gorm.DB).Select",
	"(*github.com/jinzhu/gorm.DB).Distinct",
	"(*github.com/jinzhu/gorm.DB).Pluck",
	"(*github.com/jinzhu/gorm.DB).Raw",
	"(*github.com/jinzhu/gorm.DB).Exec",
	"(*github.com/jinzhu/gorm.DB).Order",
	// GORM v2
	"(*gorm.io/gorm.DB).Where",
	"(*gorm.io/gorm.DB).Or",
	"(*gorm.io/gorm.DB).Not",
	"(*gorm.io/gorm.DB).Group",
	"(*gorm.io/gorm.DB).Having",
	"(*gorm.io/gorm.DB).Joins",
	"(*gorm.io/gorm.DB).Select",
	"(*gorm.io/gorm.DB).Distinct",
	"(*gorm.io/gorm.DB).Pluck",
	"(*gorm.io/gorm.DB).Raw",
	"(*gorm.io/gorm.DB).Exec",
	"(*gorm.io/gorm.DB).Order",
	// Alternative GORM v2 import path
	"(*github.com/go-gorm/gorm.DB).Where",
	"(*github.com/go-gorm/gorm.DB).Or",
	"(*github.com/go-gorm/gorm.DB).Not",
	"(*github.com/go-gorm/gorm.DB).Group",
	"(*github.com/go-gorm/gorm.DB).Having",
	"(*github.com/go-gorm/gorm.DB).Joins",
	"(*github.com/go-gorm/gorm.DB).Select",
	"(*github.com/go-gorm/gorm.DB).Distinct",
	"(*github.com/go-gorm/gorm.DB).Pluck",
	"(*github.com/go-gorm/gorm.DB).Raw",
	"(*github.com/go-gorm/gorm.DB).Exec",
	"(*github.com/go-gorm/gorm.DB).Order",
	// sqlx
	"(*github.com/jmoiron/sqlx.DB).Queryx",
	"(*github.com/jmoiron/sqlx.DB).QueryRowx",
	"(*github.com/jmoiron/sqlx.DB).Query",
	"(*github.com/jmoiron/sqlx.DB).QueryRow",
	"(*github.com/jmoiron/sqlx.DB).Select",
	"(*github.com/jmoiron/sqlx.DB).Get",
	"(*github.com/jmoiron/sqlx.DB).Exec",
	"(*github.com/jmoiron/sqlx.Tx).Queryx",
	"(*github.com/jmoiron/sqlx.Tx).QueryRowx",
	"(*github.com/jmoiron/sqlx.Tx).Query",
	"(*github.com/jmoiron/sqlx.Tx).QueryRow",
	"(*github.com/jmoiron/sqlx.Tx).Select",
	"(*github.com/jmoiron/sqlx.Tx).Get",
	"(*github.com/jmoiron/sqlx.Tx).Exec",
	// xorm
	"(*xorm.io/xorm.Engine).Query",
	"(*xorm.io/xorm.Engine).Exec",
	"(*xorm.io/xorm.Engine).QueryString",
	"(*xorm.io/xorm.Engine).QueryInterface",
	"(*xorm.io/xorm.Engine).SQL",
	"(*xorm.io/xorm.Engine).Where",
	"(*xorm.io/xorm.Engine).And",
	"(*xorm.io/xorm.Engine).Or",
	"(*xorm.io/xorm.Engine).Alias",
	"(*xorm.io/xorm.Engine).NotIn",
	"(*xorm.io/xorm.Engine).In",
	"(*xorm.io/xorm.Engine).Select",
	"(*xorm.io/xorm.Engine).SetExpr",
	"(*xorm.io/xorm.Engine).OrderBy",
	"(*xorm.io/xorm.Engine).Having",
	"(*xorm.io/xorm.Engine).GroupBy",
	"(*xorm.io/xorm.Engine).Join",
	"(*xorm.io/xorm.Session).Query",
	"(*xorm.io/xorm.Session).Exec",
	"(*xorm.io/xorm.Session).QueryString",
	"(*xorm.io/xorm.Session).QueryInterface",
	"(*xorm.io/xorm.Session).SQL",
	"(*xorm.io/xorm.Session).Where",
	"(*xorm.io/xorm.Session).And",
	"(*xorm.io/xorm.Session).Or",
	"(*xorm.io/xorm.Session).Alias",
	"(*xorm.io/xorm.Session).NotIn",
	"(*xorm.io/xorm.Session).In",
	"(*xorm.io/xorm.Session).Select",
	"(*xorm.io/xorm.Session).SetExpr",
	"(*xorm.io/xorm.Session).OrderBy",
	"(*xorm.io/xorm.Session).Having",
	"(*xorm.io/xorm.Session).GroupBy",
	"(*xorm.io/xorm.Session).Join",
	// Alternative xorm import path
	"(*github.com/go-xorm/xorm.Engine).Query",
	"(*github.com/go-xorm/xorm.Engine).Exec",
	"(*github.com/go-xorm/xorm.Engine).QueryString",
	"(*github.com/go-xorm/xorm.Engine).QueryInterface",
	"(*github.com/go-xorm/xorm.Engine).SQL",
	"(*github.com/go-xorm/xorm.Engine).Where",
	"(*github.com/go-xorm/xorm.Engine).And",
	"(*github.com/go-xorm/xorm.Engine).Or",
	"(*github.com/go-xorm/xorm.Engine).Alias",
	"(*github.com/go-xorm/xorm.Engine).NotIn",
	"(*github.com/go-xorm/xorm.Engine).In",
	"(*github.com/go-xorm/xorm.Engine).Select",
	"(*github.com/go-xorm/xorm.Engine).SetExpr",
	"(*github.com/go-xorm/xorm.Engine).OrderBy",
	"(*github.com/go-xorm/xorm.Engine).Having",
	"(*github.com/go-xorm/xorm.Engine).GroupBy",
	"(*github.com/go-xorm/xorm.Engine).Join",
	"(*github.com/go-xorm/xorm.Session).Query",
	"(*github.com/go-xorm/xorm.Session).Exec",
	"(*github.com/go-xorm/xorm.Session).QueryString",
	"(*github.com/go-xorm/xorm.Session).QueryInterface",
	"(*github.com/go-xorm/xorm.Session).SQL",
	"(*github.com/go-xorm/xorm.Session).Where",
	"(*github.com/go-xorm/xorm.Session).And",
	"(*github.com/go-xorm/xorm.Session).Or",
	"(*github.com/go-xorm/xorm.Session).Alias",
	"(*github.com/go-xorm/xorm.Session).NotIn",
	"(*github.com/go-xorm/xorm.Session).In",
	"(*github.com/go-xorm/xorm.Session).Select",
	"(*github.com/go-xorm/xorm.Session).SetExpr",
	"(*github.com/go-xorm/xorm.Session).OrderBy",
	"(*github.com/go-xorm/xorm.Session).Having",
	"(*github.com/go-xorm/xorm.Session).GroupBy",
	"(*github.com/go-xorm/xorm.Session).Join",
	// go-pg
	"(*github.com/go-pg/pg.DB).Query",
	"(*github.com/go-pg/pg.DB).QueryOne",
	"(*github.com/go-pg/pg.DB).Exec",
	"(*github.com/go-pg/pg.DB).ExecOne",
	"(*github.com/go-pg/pg.Tx).Query",
	"(*github.com/go-pg/pg.Tx).QueryOne",
	"(*github.com/go-pg/pg.Tx).Exec",
	"(*github.com/go-pg/pg.Tx).ExecOne",
	// rqlite
	"(*github.com/rqlite/gorqlite.Connection).Query",
	"(*github.com/rqlite/gorqlite.Connection).QueryOne",
	"(*github.com/rqlite/gorqlite.Connection).Write",
	"(*github.com/rqlite/gorqlite.Connection).WriteOne",
	"(*github.com/raindog308/gorqlite.Connection).Query",
	"(*github.com/raindog308/gorqlite.Connection).QueryOne",
	"(*github.com/raindog308/gorqlite.Connection).Write",
	"(*github.com/raindog308/gorqlite.Connection).WriteOne",
	// Squirrel
	"github.com/Masterminds/squirrel.Expr",
	"gopkg.in/Masterminds/squirrel.v1.Expr",
	"github.com/lann/squirrel.Expr",
	//
	// TODO: add more, consider (non-)pointer variants?
)

// Analyzer finds potential SQL injection issues to demonstrate
// the github.com/picatz/taint package.
var Analyzer = &analysis.Analyzer{
	Name:     "sqli",
	Doc:      "finds potential SQL injection issues",
	Run:      run,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
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
			if strings.HasSuffix(p.Path(), pkg) {
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
}

func run(pass *analysis.Pass) (interface{}, error) {
	// Require at least one supported SQL package to be imported before
	// running the analysis. This avoids wasting time analyzing programs
	// that do not use SQL.
	if !imports(pass, supportedSQLPackages...) {
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
	// we can use to identify directed paths to SQL queries.
	cg, err := callgraphutil.NewGraph(mainFn, buildSSA.SrcFuncs...)
	if err != nil {
		return nil, fmt.Errorf("failed to create new callgraph: %w", err)
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

	// Run taint check for user controlled values (sources) ending
	// up in injectable SQL methods (sinks).
	results := taint.Check(cg, userControlledValues, injectableSQLMethods)

	// For each result, check if a prepared statement is providing
	// a mitigation for the user controlled value.
	//
	// TODO: ensure this makes sense for all the GORM usage?
	for _, result := range results {
		// We found a query edge that is tainted by user input, is it
		// doing this safely? We expect this to be safely done by
		// providing a prepared statement as a constant in the query
		// (first argument after context).
		queryEdge := result.Path[len(result.Path)-1]

		// Get the query arguments. If the sink is a method call, the
		// first argument is the receiver, which we skip.
		queryArgs := queryEdge.Site.Common().Args
		if queryEdge.Site.Common().Signature().Recv() != nil {
			if len(queryArgs) < 1 {
				continue
			}
			queryArgs = queryArgs[1:]
		}

		// Skip the context argument, if using a *Context query variant.
		if strings.HasSuffix(queryEdge.Site.Value().Call.Value.String(), "Context") {
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

		// Ensure it is a constant (prepared statement), otherwise report
		// potential SQL injection.
		if _, isConst := query.(*ssa.Const); !isConst {
			pass.Reportf(result.SinkValue.Pos(), "potential sql injection")
		}
	}

	return nil, nil
}
