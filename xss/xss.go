package xss

import (
    "fmt"
    "flag"
    "strings"
    "os"
    "go/types"

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

	// fmt.Println(cg)

	// Run taint check for user controlled values (sources) ending
	// up in injectable log functions (sinks).
	results := taint.Check(cg, userControlledValues, injectableFunctions)

    dbg("results: %d", len(results))

    for _, result := range results {
        dbg("path: %s", result.Path.String())
        // Fast suppression: if any function (caller or callee) along the path
        // includes html.EscapeString, consider the flow sanitized and skip.
        pathHasEscape := false
        for _, e := range result.Path {
            if e != nil {
                if e.Callee != nil && e.Callee.Func != nil && funcHasHtmlEscape(e.Callee.Func) {
                    pathHasEscape = true
                    break
                }
                if e.Caller != nil && e.Caller.Func != nil && funcHasHtmlEscape(e.Caller.Func) {
                    pathHasEscape = true
                    break
                }
            }
        }
        if pathHasEscape {
            dbg("suppressed: pathHasEscape=true")
            continue
        }
        // Identify the concrete sink callsite by scanning the path backwards for
        // an invoke of Write/WriteHeader. This avoids misidentifying helper calls.
        var sinkEdge *callgraph.Edge
        for i := len(result.Path) - 1; i >= 0; i-- {
            e := result.Path[i]
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
                    sinkEdge = e
                    break
                }
            }
        }
        // Fallback to last edge if not found (should be rare)
        if sinkEdge == nil && len(result.Path) > 0 {
            sinkEdge = result.Path[len(result.Path)-1]
        }
        if sinkEdge != nil && sinkEdge.Site != nil && sinkEdge.Caller != nil && sinkEdge.Callee != nil && sinkEdge.Callee.Func != nil {
            dbg("sinkEdge: caller=%s callee=%s", sinkEdge.Caller.Func.String(), sinkEdge.Callee.Func.String())
        }
        // Determine the function that contains the sink callsite (caller)
        var callerFunc *ssa.Function
        if sinkEdge.Caller != nil {
            callerFunc = sinkEdge.Caller.Func
        }

        // Check whether caller applies html.EscapeString anywhere
        escaped := false
        if callerFunc != nil && funcHasHtmlEscape(callerFunc) {
            escaped = true
            dbg("suppressed: caller func has html.EscapeString: %s", callerFunc.String())
        }

        // Also check the callee function of the (potential) sink edge; some paths may
        // have selected the call into a helper (e.g., echoSafe) as the last edge.
        if !escaped && sinkEdge.Callee != nil && sinkEdge.Callee.Func != nil && funcHasHtmlEscape(sinkEdge.Callee.Func) {
            escaped = true
            dbg("suppressed: callee func has html.EscapeString: %s", sinkEdge.Callee.Func.String())
        }

        if !escaped {
            // Fallback: scan all functions in the path for html.EscapeString
            for _, edge := range result.Path {
                if edge != nil && edge.Callee != nil && edge.Callee.Func != nil {
                    for _, block := range edge.Callee.Func.Blocks {
                        for _, instr := range block.Instrs {
                            if call, ok := instr.(*ssa.Call); ok {
                                if isHtmlEscapeCall(call) {
                                    escaped = true
                                    dbg("suppressed: path callee contains html.EscapeString in %s", edge.Callee.Func.String())
                                    break
                                }
                            }
                        }
                        if escaped {
                            break
                        }
                    }
                }
                if escaped {
                    break
                }
            }
        }

        // Choose report site:
        // Prefer a user-package callsite to the function containing the sink (e.g., echoUnsafe → io.Writer.Write).
        // If none, fall back to the sink callsite.
        var reportEdge *callgraph.Edge
        var containerFunc *ssa.Function
        if sinkEdge != nil && sinkEdge.Caller != nil {
            containerFunc = sinkEdge.Caller.Func
        }
        if containerFunc != nil {
            var userEdges []*callgraph.Edge
            for _, n := range cg.Nodes {
                for _, e2 := range n.Out {
                    if e2 == nil || e2.Site == nil || e2.Callee == nil || e2.Callee.Func == nil || e2.Caller == nil || e2.Caller.Func == nil || e2.Caller.Func.Pkg == nil || e2.Caller.Func.Pkg.Pkg == nil {
                        continue
                    }
                    if e2.Callee.Func != containerFunc {
                        continue
                    }
                    if e2.Caller.Func.Pkg.Pkg.Path() == pass.Pkg.Path() {
                        userEdges = append(userEdges, e2)
                    }
                }
            }
            if debugXSS {
                for _, ue := range userEdges {
                    dbg("userEdge: caller=%s → callee=%s", ue.Caller.Func.String(), ue.Callee.Func.String())
                }
            }
            // Partition by sanitization presence in caller function
            var unsanitized, sanitized []*callgraph.Edge
            for _, ue := range userEdges {
                if funcHasHtmlEscape(ue.Caller.Func) {
                    sanitized = append(sanitized, ue)
                } else {
                    unsanitized = append(unsanitized, ue)
                }
            }
            if len(unsanitized) > 0 {
                reportEdge = unsanitized[0]
                dbg("selected unsanitized userEdge caller=%s", reportEdge.Caller.Func.String())
            } else if len(sanitized) > 0 {
                // If only sanitized callsites exist, suppress
                escaped = true
                dbg("suppressed: only sanitized userEdges present")
            }
        }
        if reportEdge == nil {
            // Fallback: inspect the function that contains the sink callsite's parent (e.g., handler)
            // and report at a direct call to a user function that does not sanitize (e.g., echoUnsafe).
            if sinkEdge != nil && sinkEdge.Caller != nil {
                parent := sinkEdge.Caller.Func
                if parent != nil {
                    for _, block := range parent.Blocks {
                        for _, instr := range block.Instrs {
                            if call, ok := instr.(*ssa.Call); ok {
                                // consider only direct calls to user functions
                                if fn, ok2 := call.Call.Value.(*ssa.Function); ok2 && fn != nil && fn.Pkg != nil && fn.Pkg.Pkg != nil && fn.Pkg.Pkg.Path() == pass.Pkg.Path() {
                                    // prefer calls whose target does NOT contain html.EscapeString (unsafe)
                                    if !funcHasHtmlEscape(fn) {
                                        // fabricate a minimal edge-like holder for reporting
                                        reportEdge = &callgraph.Edge{Site: call, Caller: sinkEdge.Caller, Callee: cg.CreateNode(fn)}
                                        break
                                    }
                                }
                            }
                        }
                        if reportEdge != nil {
                            break
                        }
                    }
                }
            }
            if reportEdge == nil {
                reportEdge = sinkEdge
            }
        }
        if reportEdge == nil || reportEdge.Site == nil {
            continue
        }

        // Last-mile check: inspect the sink argument expression for escaping.
        if sinkEdge != nil && sinkEdge.Site != nil {
            args := sinkEdge.Site.Common().Args
            if sig := sinkEdge.Site.Common().Signature(); sig != nil && sig.Recv() != nil && len(args) > 0 {
                args = args[1:]
            }
            if len(args) > 0 {
                // Last-mile: if argument expression includes html.EscapeString, suppress
                if hasHtmlEscape(args[0]) {
                    escaped = true
                    dbg("suppressed: sink arg contains html.EscapeString")
                }
            }
        }

        if !escaped {
            dbg("reporting at site")
            pass.Reportf(reportEdge.Site.Pos(), "potential XSS")
        }
    }

    return nil, nil
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
