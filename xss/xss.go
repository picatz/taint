package xss

import (
	"context"
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
	"fmt.Fprint",
	"fmt.Fprintf",
	"fmt.Fprintln",
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
var callGraphAlgorithm = string(callgraphutil.CallGraphAlgorithmTaint)

func init() {
	// Add a "-debug" flag to the analyzer.
	fs := flag.NewFlagSet("xss", flag.ContinueOnError)
	fs.BoolVar(&debugXSS, "debug", false, "enable debug logging for xss analyzer")
	fs.StringVar(&callGraphAlgorithm, "callgraph", callGraphAlgorithm, "callgraph algorithm: taint or vta")
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

		// Destination provenance filter. The sink rule (io.Writer).Write
		// matches any Write on any io.Writer, including writes to log
		// buffers (*bytes.Buffer), *strings.Builder, *os.File, etc. — none
		// of which are HTTP response surfaces. Reject the finding only when
		// the destination is *provably* a non-ResponseWriter; preserve
		// detection when the destination flows from a ResponseWriter and
		// when its origin cannot be statically determined (channel handoff,
		// opaque interface, recursion limit, etc.). This is a tristate
		// filter, not a binary one — we never drop detection on unclear
		// provenance.
		if destinationProvenance(sinkDestination(sinkEdge), result.Path) == provNotResponseWriter {
			dbg("filtered: sink destination provably not a ResponseWriter")
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

// destProv is the tristate verdict from destinationProvenance.
type destProv int

const (
	// provUnknown means the destination's origin cannot be determined
	// statically. The finding is preserved on unknown — under-tainting
	// silently is worse than over-tainting visibly.
	provUnknown destProv = iota
	// provResponseWriter means the destination provably flows from an
	// http.ResponseWriter typed value (parameter, field, or convertible).
	provResponseWriter
	// provNotResponseWriter means the destination provably allocates a
	// concrete non-response writer type — bytes.Buffer, strings.Builder,
	// os.File, etc. This is the only verdict that suppresses the finding.
	provNotResponseWriter
)

// sinkDestination returns the SSA value that the sink writes into.
//
//   - (io.Writer).Write — destination is the Invoke receiver (Common.Value)
//   - io.Copy(dst, src) — destination is Args[0]
//   - io.WriteString(w, s) — destination is Args[0]
//   - (net/http.ResponseWriter).Write/WriteHeader — destination is the
//     receiver; these are already ResponseWriter-typed at the sink rule
//     level, so the filter is a no-op but kept for uniformity.
//
// Returns nil if the destination cannot be located, in which case the
// filter degrades to "preserve finding" (provUnknown semantics at the
// caller).
func sinkDestination(edge *callgraph.Edge) ssa.Value {
	if edge == nil || edge.Site == nil {
		return nil
	}
	cc := edge.Site.Common()
	if cc == nil {
		return nil
	}
	calleeID := ""
	if edge.Callee != nil && edge.Callee.Func != nil {
		calleeID = edge.Callee.Func.String()
	}
	// Invoke calls on io.Writer or net/http.ResponseWriter: destination is
	// the receiver, which lives in Common.Value (not Args).
	if cc.IsInvoke() {
		return cc.Value
	}
	// Function-form sinks: io.Copy(dst, src), io.WriteString(w, s), and
	// fmt.Fprint/Fprintf/Fprintln(w, ...). All place the destination at
	// Args[0].
	switch calleeID {
	case "fmt.Fprint", "fmt.Fprintf", "fmt.Fprintln", "io.Copy", "io.WriteString":
		if len(cc.Args) > 0 {
			return cc.Args[0]
		}
	}
	// Non-invoke method calls (rare for our sinks but handle): receiver is
	// Args[0].
	if cc.Signature() != nil && cc.Signature().Recv() != nil && len(cc.Args) > 0 {
		return cc.Args[0]
	}
	return nil
}

// destinationProvenance walks v's data dependencies to classify whether it
// flows from an HTTP response surface. The walker is intentionally
// asymmetric: it returns provNotResponseWriter ONLY when every reaching
// definition is a concrete non-response writer allocation; provUnknown is
// the default when any reaching definition is opaque (channel, map index,
// foreign call, recursion limit). This bias preserves detection on flows
// the walker cannot fully resolve.
//
// The taint path is used to resolve *ssa.Parameter encounters: when v is a
// parameter of a function on the path, we walk back to the call site and
// inspect the caller's argument. Without this, helpers like chi's `cW`
// would always report provUnknown for their `io.Writer` parameter and the
// filter could never fire on intermediate buffer writes.
func destinationProvenance(v ssa.Value, path callgraphutil.Path) destProv {
	if v == nil {
		return provUnknown
	}
	seen := map[ssa.Value]struct{}{}
	var walk func(ssa.Value) destProv
	walk = func(cur ssa.Value) destProv {
		if cur == nil {
			return provUnknown
		}
		if _, dup := seen[cur]; dup {
			return provUnknown
		}
		seen[cur] = struct{}{}

		// Symmetric type check: definite yes / definite no decisions based
		// on the value's static type alone, before walking operands.
		// Catches dereferences and casts where the SSA case below would
		// fall through to provUnknown despite the type being conclusive.
		if isResponseWriterType(cur.Type()) {
			return provResponseWriter
		}
		if isKnownNonResponseWriterType(cur.Type()) {
			return provNotResponseWriter
		}

		switch x := cur.(type) {
		case *ssa.Parameter:
			// Resolve parameter to caller argument via the taint path.
			// Walking the actual flow lets us classify destinations like
			// chi's cW(&buf, ...) where `w` inside cW is a parameter but
			// the caller passed a known buffer.
			if arg := callerArgForParameter(path, x); arg != nil {
				return walk(arg)
			}
			return provUnknown
		case *ssa.MakeInterface:
			return walk(x.X)
		case *ssa.ChangeInterface:
			return walk(x.X)
		case *ssa.ChangeType:
			return walk(x.X)
		case *ssa.Convert:
			return walk(x.X)
		case *ssa.TypeAssert:
			return walk(x.X)
		case *ssa.FieldAddr:
			if isKnownNonResponseWriterType(x.Type()) {
				return provNotResponseWriter
			}
			return provUnknown
		case *ssa.UnOp:
			if x.Op == token.MUL {
				return walk(x.X)
			}
			return provUnknown
		case *ssa.Alloc:
			if isKnownNonResponseWriterType(x.Type()) {
				return provNotResponseWriter
			}
			return provUnknown
		case *ssa.Global:
			if isKnownNonResponseWriterType(x.Type()) {
				return provNotResponseWriter
			}
			return provUnknown
		case *ssa.Call:
			// A function returning the destination — without a return-type
			// analysis we cannot prove the result is a non-response
			// writer, so be conservative and return unknown. This is the
			// case for bufio.NewWriter(w), bytes.NewBuffer(...), and any
			// custom factory function.
			return provUnknown
		case *ssa.Phi:
			var verdict destProv = -1
			for _, e := range x.Edges {
				p := walk(e)
				if p == provUnknown {
					return provUnknown
				}
				if verdict == -1 {
					verdict = p
					continue
				}
				if verdict != p {
					return provUnknown
				}
			}
			if verdict == -1 {
				return provUnknown
			}
			return verdict
		}
		return provUnknown
	}
	return walk(v)
}

// callerArgForParameter walks the taint path to find the call edge that
// targets the function containing the parameter, then returns the
// corresponding argument from the caller's call site. Returns nil if the
// parameter's parent function does not appear as a callee on the path or
// the call site does not have an argument at the parameter's index.
func callerArgForParameter(path callgraphutil.Path, p *ssa.Parameter) ssa.Value {
	if p == nil || p.Parent() == nil {
		return nil
	}
	parent := p.Parent()
	paramIdx := -1
	for i, fp := range parent.Params {
		if fp == p {
			paramIdx = i
			break
		}
	}
	if paramIdx < 0 {
		return nil
	}
	for _, edge := range path {
		if edge == nil || edge.Site == nil {
			continue
		}
		if edge.Callee == nil || edge.Callee.Func != parent {
			continue
		}
		common := edge.Site.Common()
		if common == nil {
			continue
		}
		// For Invoke calls Args excludes the receiver; for non-invoke
		// method calls Args includes the receiver as Args[0]. Parameters
		// likewise include the receiver as Params[0] for methods, so the
		// indices align directly in the non-invoke case. For Invoke calls
		// the receiver is in Common.Value; shift the param index down by
		// one if the parent has a receiver.
		argIdx := paramIdx
		if common.IsInvoke() && parent.Signature.Recv() != nil {
			if paramIdx == 0 {
				return common.Value
			}
			argIdx = paramIdx - 1
		}
		if argIdx < 0 || argIdx >= len(common.Args) {
			continue
		}
		return common.Args[argIdx]
	}
	return nil
}

// isResponseWriterType returns true for values typed as net/http.ResponseWriter
// (the interface) or implementations thereof that we can recognize from
// type strings alone. We deliberately match on the interface name because
// chasing implementation relationships through go/types here is more
// machinery than the precision win warrants.
func isResponseWriterType(t types.Type) bool {
	if t == nil {
		return false
	}
	s := t.String()
	return s == "net/http.ResponseWriter" || s == "*net/http.ResponseWriter"
}

// isKnownNonResponseWriterType returns true for a curated allowlist of
// stdlib types that are unambiguously not HTTP response surfaces in their
// own right.
//
// The audit policy: a type belongs here only if (a) its Write/WriteString
// implementations are confined to that type's owned storage (an in-memory
// slice, a string buffer, an OS file descriptor, a log stream) and (b) any
// downstream flush to an HTTP response surface happens via a *different*
// call (e.g. (*bytes.Buffer).WriteTo, w.Write(buf.Bytes()), io.Copy(w, buf))
// which the engine catches independently at the real ResponseWriter sink.
//
// Notable exclusions and their reasons:
//
//   - *bufio.Writer wraps an io.Writer that is commonly an
//     http.ResponseWriter; bw.Write(tainted) followed by bw.Flush() reaches
//     the wrapped writer. Excluded so wrapping a ResponseWriter still fires.
//   - tabwriter, gzip.Writer, anything else that explicitly wraps another
//     io.Writer at construction time. Same reasoning.
//   - io.Pipe writers (an *io.PipeWriter feeds a paired Reader that the
//     handler might serve). Excluded out of caution.
//
// Kept deliberately small. When in doubt, leave a type out and let
// provUnknown preserve the finding — under-tainting silently is worse than
// over-tainting visibly.
func isKnownNonResponseWriterType(t types.Type) bool {
	if t == nil {
		return false
	}
	switch t.String() {
	case "*bytes.Buffer",
		"bytes.Buffer",
		"*strings.Builder",
		"strings.Builder",
		"*os.File",
		"*log.Logger":
		return true
	}
	return false
}
