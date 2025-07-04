package injection

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/picatz/taint"
	"github.com/picatz/taint/callgraphutil"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
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

// findModuleRoot searches upward from the given directory until a go.mod file is
// found. If no module file is found, the original directory is returned.
func findModuleRoot(dir string) string {
	start := dir
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return start
		}
		dir = parent
	}
}

func run(pass *analysis.Pass) (interface{}, error) {
	// Require the database/sql or GORM v1 packages are imported in the
	// program being analyzed before running the analysis.
	//
	// This prevents wasting time analyzing programs that don't use SQL.
	if !imports(pass, "database/sql", "github.com/jinzhu/gorm") {
		return nil, nil
	}

	_ = pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)

	// Determine the module root so we can load all packages with source
	// information. This allows building a complete call graph across
	// package boundaries.
	pkgDir := filepath.Dir(pass.Fset.File(pass.Files[0].Pos()).Name())
	modRoot := findModuleRoot(pkgDir)

	pkgs, err := packages.Load(&packages.Config{Mode: packages.LoadAllSyntax, Dir: modRoot}, "./...")
	if err != nil {
		return nil, fmt.Errorf("failed to load packages: %w", err)
	}

	prog, ssaPkgs := ssautil.Packages(pkgs, ssa.InstantiateGenerics)
	prog.Build()

	var mainFn *ssa.Function
	for _, p := range ssautil.MainPackages(ssaPkgs) {
		if m := p.Func("main"); m != nil {
			mainFn = m
			break
		}
	}
	if mainFn == nil {
		return nil, nil
	}

	var allFns []*ssa.Function
	for fn := range ssautil.AllFunctions(prog) {
		allFns = append(allFns, fn)
	}

	// Construct a call graph using all discovered functions.
	cg, err := callgraphutil.NewGraph(mainFn, allFns...)
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

	// Note: this actually panis for testcase b
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
