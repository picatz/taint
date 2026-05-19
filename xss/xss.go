package xss

import (
	"flag"
	"fmt"
	"go/token"
	"go/types"
	"os"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	"github.com/picatz/taint"
	"github.com/picatz/taint/callgraphutil"
)

var userControlledValues = taint.NewSources(
	"*net/http.Request",
)

var injectableFunctions = taint.NewSinks(
	// Note: at this time, they *must* be a function or method.
	"(net/http.ResponseWriter).Write",
	"(net/http.ResponseWriter).WriteHeader",
	"(io.Writer).Write",
	"io.Copy",
	"io.WriteString",
)

// Analyzer finds potential XSS issues.
var Analyzer = &analysis.Analyzer{
	Name:     "xss",
	Doc:      "finds potential XSS issues",
	Run:      run,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

// debugXSS enables verbose debug logging for this analyzer.
var debugXSS bool

func init() {
	// Add a "-debug" flag to the analyzer.
	fs := flag.NewFlagSet("xss", flag.ContinueOnError)
	fs.BoolVar(&debugXSS, "debug", false, "enable debug logging for xss analyzer")
	Analyzer.Flags = *fs
	// Also honor environment variable for convenience.
	if os.Getenv("XSS_DEBUG") != "" {
		debugXSS = true
	}
}

func dbg(format string, args ...interface{}) {
	if debugXSS {
		fmt.Fprintf(os.Stderr, "[xss-debug] "+format+"\n", args...)
	}
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

func run(pass *analysis.Pass) (any, error) {
	// Require the log package is imported in the
	// program being analyzed before running the analysis.
	//
	// This prevents wasting time analyzing programs that don't log.
	if !imports(pass, "net/http") {
		return nil, nil
	}

	// Get the built SSA IR.
	buildSSA := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)

	// Identify the main function from the package's SSA IR.
	mainFn := buildSSA.Pkg.Func("main")

	// Construct a callgraph, using the main function as the root,
	// constructed of all other functions. This returns a callgraph
	// we can use to identify directed paths to logging functions.
	var cg *callgraph.Graph
	var err error
	if mainFn != nil {
		cg, err = callgraphutil.NewGraph(mainFn, buildSSA.SrcFuncs...)
	} else {
		cg, _, err = callgraphutil.CreateMultiRootCallGraph(buildSSA.Pkg.Prog, buildSSA.SrcFuncs)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create callgraph: %w", err)
	}

	// fmt.Println(cg)

	// Run taint check for user controlled values (sources) ending
	// up in injectable log functions (sinks).
	diagnostics := taint.CheckDetailed(cg, userControlledValues, injectableFunctions, taint.WithSanitizers("html.EscapeString"))

	dbg("results: %d", len(diagnostics))

	// Dedupe report positions: two taint flows that converge on the same
	// user callsite (e.g. both reach the same logging helper) produce
	// identical findings from the user's perspective, and reporting them
	// twice is noise.
	reported := map[token.Pos]struct{}{}
	for _, diagnostic := range diagnostics {
		result := diagnostic.Result
		dbg("path: %s", result.Path.String())
		if debugXSS {
			for _, evidence := range diagnostic.Evidence {
				dbg("evidence: %s rule=%s msg=%s", evidence.Kind, evidence.Rule, evidence.Message)
			}
		}

		sinkEdge := findResponseWriterSinkEdge(result.Path)
		if sinkEdge == nil || sinkEdge.Site == nil {
			continue
		}

		// Pick the outermost call site on this specific taint path that lives
		// inside the user's package. Walking the path itself (rather than the
		// whole call graph) keeps the report stable: the same logical taint
		// flow always surfaces at the same source line, even when the
		// container helper is invoked from many places in the codebase.
		reportEdge := userCallsiteOnPath(result.Path, pass.Pkg.Path(), sinkEdge)
		if reportEdge == nil {
			reportEdge = userCallsiteForContainer(cg, pass.Pkg.Path(), sinkEdge)
		}
		if reportEdge == nil {
			reportEdge = sinkEdge
		}
		if reportEdge == nil || reportEdge.Site == nil {
			continue
		}

		pos := reportEdge.Site.Pos()
		if _, ok := reported[pos]; ok {
			continue
		}
		reported[pos] = struct{}{}

		dbg("reporting at site")
		pass.Reportf(pos, "potential XSS")
	}

	return nil, nil
}

// userCallsiteOnPath inspects the edge immediately preceding the sink on
// the taint path. If that edge is the user's call into a helper that ends
// up writing (caller lives in pkgPath), it is returned so the diagnostic
// surfaces at the line where the user passed tainted data into the
// helper, not at the inner Write line that is the same for every call to
// that helper.
//
// When the preceding edge is itself out-of-package — for example, the
// sink is invoked directly from a user closure that the HTTP framework
// dispatches — this returns nil so the caller can fall back to reporting
// at the sink site itself. That preserves the existing behavior for
// straightforward "closure writes a request value directly" cases.
//
// Walking only one step back keeps the reported line tied to *this*
// specific taint flow. Walking further would surface registration call
// sites or unrelated user code that does not actually flow taint.
func userCallsiteOnPath(path callgraphutil.Path, pkgPath string, sinkEdge *callgraph.Edge) *callgraph.Edge {
	if pkgPath == "" {
		return nil
	}
	sinkIdx := -1
	for i, e := range path {
		if e == sinkEdge {
			sinkIdx = i
			break
		}
	}
	if sinkIdx < 1 {
		return nil
	}
	e := path[sinkIdx-1]
	if e == nil || e.Site == nil || e.Caller == nil || e.Caller.Func == nil {
		return nil
	}
	pkg := e.Caller.Func.Pkg
	if pkg == nil || pkg.Pkg == nil {
		return nil
	}
	if pkg.Pkg.Path() != pkgPath {
		return nil
	}
	return e
}

func findResponseWriterSinkEdge(path callgraphutil.Path) *callgraph.Edge {
	for i := len(path) - 1; i >= 0; i-- {
		e := path[i]
		if e == nil || e.Site == nil {
			continue
		}
		cc := e.Site.Common()
		if cc == nil {
			continue
		}
		if cc.IsInvoke() && cc.Method != nil {
			name := cc.Method.Name()
			if name == "Write" || name == "WriteHeader" {
				return e
			}
		}
	}
	if len(path) == 0 {
		return nil
	}
	return path[len(path)-1]
}

func sinkArgumentEscaped(edge *callgraph.Edge) bool {
	if edge == nil || edge.Site == nil {
		return false
	}
	args := edge.Site.Common().Args
	if sig := edge.Site.Common().Signature(); sig != nil && sig.Recv() != nil && len(args) > 0 {
		args = args[1:]
	}
	return len(args) > 0 && hasHtmlEscape(args[0])
}

// userCallsiteForContainer finds the in-package call edge that invokes the
// container function of the sink (e.g. the http handler containing
// w.Write(taintedData)). It returns the call site we want to surface to the
// user rather than the deeper sink location.
//
// The candidate edges are collected from all nodes whose Out slice targets
// containerFunc. Because cg.Nodes is a map, iteration order is randomized
// between runs; we therefore collect every candidate first and then pick a
// canonical representative by source position so the reported finding is
// stable. Without this, the same logical taint flow reports at a different
// line each run when multiple call paths lead into the container.
func userCallsiteForContainer(cg *callgraph.Graph, pkgPath string, sinkEdge *callgraph.Edge) *callgraph.Edge {
	if cg == nil || sinkEdge == nil || sinkEdge.Caller == nil || sinkEdge.Caller.Func == nil {
		return nil
	}
	containerFunc := sinkEdge.Caller.Func
	var best *callgraph.Edge
	for _, n := range cg.Nodes {
		for _, e := range n.Out {
			if e == nil || e.Site == nil || e.Callee == nil || e.Callee.Func != containerFunc {
				continue
			}
			if e.Caller == nil || e.Caller.Func == nil || e.Caller.Func.Pkg == nil || e.Caller.Func.Pkg.Pkg == nil {
				continue
			}
			if e.Caller.Func.Pkg.Pkg.Path() != pkgPath {
				continue
			}
			if best == nil || edgePosLess(e, best) {
				best = e
			}
		}
	}
	return best
}

// edgePosLess orders edges by the source position of the call site, then by
// callee identity. Equivalent to the canonical ordering applied to node.Out
// during callgraph construction, used here when picking the representative
// candidate across multiple nodes.
func edgePosLess(a, b *callgraph.Edge) bool {
	ap, bp := edgeSitePos(a), edgeSitePos(b)
	if ap != bp {
		return ap < bp
	}
	return edgeCalleeKey(a) < edgeCalleeKey(b)
}

func edgeSitePos(e *callgraph.Edge) token.Pos {
	if e == nil || e.Site == nil {
		return token.NoPos
	}
	return e.Site.Pos()
}

func edgeCalleeKey(e *callgraph.Edge) string {
	if e == nil || e.Callee == nil || e.Callee.Func == nil {
		return ""
	}
	return e.Callee.Func.String()
}

// funcHasHtmlEscape returns true if any instruction in the function calls html.EscapeString.
func funcHasHtmlEscape(f *ssa.Function) bool {
	if f == nil {
		return false
	}
	for _, block := range f.Blocks {
		for _, instr := range block.Instrs {
			if call, ok := instr.(*ssa.Call); ok {
				if isHtmlEscapeCall(call) {
					return true
				}
			}
		}
	}
	return false
}

// hasHtmlEscape returns true if the value's expression tree contains a call to html.EscapeString.
func hasHtmlEscape(v ssa.Value) bool {
	seen := map[ssa.Value]struct{}{}
	work := []ssa.Value{v}
	for len(work) > 0 {
		cur := work[len(work)-1]
		work = work[:len(work)-1]
		if cur == nil {
			continue
		}
		if _, ok := seen[cur]; ok {
			continue
		}
		seen[cur] = struct{}{}

		if call, ok := cur.(*ssa.Call); ok {
			if isHtmlEscapeCall(call) {
				return true
			}
			// explore call operands
			for _, a := range call.Call.Args {
				if a != nil {
					work = append(work, a)
				}
			}
		}

		if instr, ok := cur.(ssa.Instruction); ok {
			ops := instr.Operands(nil)
			for _, p := range ops {
				if p != nil && *p != nil {
					work = append(work, *p)
				}
			}
		}
		// Follow common single-operand wrappers explicitly (helps when not Instruction)
		switch x := cur.(type) {
		case *ssa.MakeInterface:
			work = append(work, x.X)
		case *ssa.Convert:
			work = append(work, x.X)
		case *ssa.ChangeType:
			work = append(work, x.X)
		case *ssa.UnOp:
			work = append(work, x.X)
			if x.Op == token.MUL {
				work = append(work, storedValues(x.X)...)
			}
		case *ssa.Alloc:
			work = append(work, storedValues(x)...)
		case *ssa.Extract:
			work = append(work, x.Tuple)
		case *ssa.Slice:
			work = append(work, x.X)
		case *ssa.IndexAddr:
			work = append(work, x.X)
		case *ssa.FieldAddr:
			work = append(work, x.X)
		}
	}
	return false
}

func storedValues(addr ssa.Value) []ssa.Value {
	if addr == nil {
		return nil
	}
	var out []ssa.Value
	if refs := addr.Referrers(); refs != nil {
		for _, ref := range *refs {
			store, ok := ref.(*ssa.Store)
			if !ok || store.Addr != addr || store.Val == nil {
				continue
			}
			out = append(out, store.Val)
		}
	}
	return out
}

// isHtmlEscapeCall determines if a call is to html.EscapeString using package/type info, not strings.
func isHtmlEscapeCall(call *ssa.Call) bool {
	if call == nil || call.Call.Value == nil {
		return false
	}
	if fn, ok := call.Call.Value.(*ssa.Function); ok {
		// Ensure it’s the standard library html package
		if fn.Pkg != nil && fn.Pkg.Pkg != nil && fn.Pkg.Pkg.Path() == "html" && fn.Name() == "EscapeString" {
			return true
		}
	}
	return false
}

// argIsUserControlled returns true if the SSA value depends on *net/http.Request inputs.
func argIsUserControlled(v ssa.Value) bool {
	seen := map[ssa.Value]struct{}{}
	work := []ssa.Value{v}
	for len(work) > 0 {
		cur := work[len(work)-1]
		work = work[:len(work)-1]
		if cur == nil {
			continue
		}
		if _, ok := seen[cur]; ok {
			continue
		}
		seen[cur] = struct{}{}

		// Direct type check
		if isHTTPRequestType(cur.Type()) {
			return true
		}

		// If this is a field address, check the base expression type (e.g., r.URL, r.Body)
		if fa, ok := cur.(*ssa.FieldAddr); ok {
			if isHTTPRequestType(fa.X.Type()) {
				return true
			}
		}

		// Explore operands for instructions
		if instr, ok := cur.(ssa.Instruction); ok {
			ops := instr.Operands(nil)
			for _, p := range ops {
				if p != nil && *p != nil {
					work = append(work, *p)
				}
			}
		}
		// Explore common single-operand wrappers
		switch x := cur.(type) {
		case *ssa.MakeInterface:
			work = append(work, x.X)
		case *ssa.Convert:
			work = append(work, x.X)
		case *ssa.ChangeType:
			work = append(work, x.X)
		case *ssa.UnOp:
			work = append(work, x.X)
		case *ssa.Extract:
			work = append(work, x.Tuple)
		case *ssa.Slice:
			work = append(work, x.X)
		case *ssa.IndexAddr:
			work = append(work, x.X)
		case *ssa.FieldAddr:
			work = append(work, x.X)
		case *ssa.Call:
			// Explore call arguments
			for _, a := range x.Call.Args {
				if a != nil {
					work = append(work, a)
				}
			}
		}
	}
	return false
}

func isHTTPRequestType(t types.Type) bool {
	if t == nil {
		return false
	}
	// Accept exact string match for robustness across testdata GOPATH/module modes
	return t.String() == "*net/http.Request"
}
