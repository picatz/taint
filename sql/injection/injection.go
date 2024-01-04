package injection

import (
	"fmt"
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
	// Function (and method) calls
	// "(net/url.Values).Get",
	// "(*net/url.URL).Query",
	// "(*net/url.URL).Redacted",
	// "(*net/url.URL).EscapedFragment",
	// "(*net/url.Userinfo).Username",
	// "(*net/url.Userinfo).Passworde",
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
	// TODO: consider supprot for gRPC request metadata (HTTP2 headers)
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
	// Require the database/sql or GORM v1 packages are imported in the
	// program being analyzed before running the analysis.
	//
	// This prevents wasting time analyzing programs that don't use SQL.
	if !imports(pass, "database/sql", "github.com/jinzhu/gorm") {
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
	cg, err := callgraphutil.NewCallGraph(mainFn, buildSSA.SrcFuncs...)
	if err != nil {
		return nil, fmt.Errorf("failed to create new callgraph: %w", err)
	}

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

		// Get the query arguments, skipping the first element, pointer to the DB.
		queryArgs := queryEdge.Site.Common().Args[1:]

		// Skip the context argument, if using a *Context query variant.
		if strings.HasPrefix(queryEdge.Site.Value().Call.Value.String(), "Context") {
			queryArgs = queryArgs[1:]
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
