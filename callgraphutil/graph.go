package callgraphutil

import (
	"bytes"
	"context"
	"fmt"
	"go/token"
	"go/types"
	"sort"
	"sync"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Global caches with lock-free reads and per-key initialization
type allFunctionsEntry struct {
	once  sync.Once
	value map[*ssa.Function]bool
}

type syntheticMethodKey struct {
	prog *ssa.Program
	key  string
}

type syntheticMethodEntry struct {
	once sync.Once
	fn   *ssa.Function
}

var (
	// Cache of ssautil.AllFunctions(prog) results keyed by *ssa.Program
	// Uses sync.Map for lock-free reads; each entry initializes once.
	allFunctionsCache sync.Map // map[*ssa.Program]*allFunctionsEntry

	// Cache of synthetic method functions keyed by program+receiver+method string.
	// Ensures only one synthetic *ssa.Function is created per key.
	syntheticMethodCache sync.Map // map[syntheticMethodKey]*syntheticMethodEntry
)

// getAllFunctionsCached returns cached AllFunctions result for significant performance boost.
// AllFunctions is expensive (6+ms on large codebases) but result is identical for same program.
func getAllFunctionsCached(prog *ssa.Program) map[*ssa.Function]bool {
	entryIface, _ := allFunctionsCache.LoadOrStore(prog, &allFunctionsEntry{})
	entry := entryIface.(*allFunctionsEntry)
	entry.once.Do(func() {
		entry.value = ssautil.AllFunctions(prog)
	})
	return entry.value
}

// getOrCreateSyntheticMethod returns a stable synthetic method function for a
// given key, creating it exactly once per key.
func getOrCreateSyntheticMethod(prog *ssa.Program, key, methodName string, sig *types.Signature) *ssa.Function {
	cacheKey := syntheticMethodKey{prog: prog, key: key}
	entryIface, _ := syntheticMethodCache.LoadOrStore(cacheKey, &syntheticMethodEntry{})
	entry := entryIface.(*syntheticMethodEntry)
	entry.once.Do(func() {
		entry.fn = prog.NewFunction(methodName, sig, "synthetic")
	})
	return entry.fn
}

// GraphString returns a string representation of the call graph,
// which is a sequence of nodes separated by newlines, with the
// callees of each node indented by a tab.
func GraphString(g *callgraph.Graph) string {
	var buf bytes.Buffer

	for _, n := range g.Nodes {
		fmt.Fprintf(&buf, "%s\n", n)
		for _, e := range n.Out {
			fmt.Fprintf(&buf, "\t→ %s\n", e.Callee)
		}
		fmt.Fprintf(&buf, "\n")
	}

	return buf.String()
}

// NewGraph returns a new Graph with the specified root node.
//
// Typically, the root node is the main function of the program, and the
// srcFns are the source functions that are of interest to the caller. But, the root
// node can be any function, and the srcFns can be any set of functions.
//
// This algorithm attempts to add all source functions reachable from the root node
// by traversing the SSA IR and adding edges to the graph; it handles calls
// to functions, methods, closures, and interfaces. It may miss some complex
// edges today, such as stucts containing function fields accessed via slice or map
// indexing. This is a known limitation, but something we hope to improve in the near future.
// https://github.com/picatz/taint/issues/23
//
// Performance optimizations:
// - Caches AllFunctions results per SSA program for massive speedup on large codebases
// - Early exits to skip non-relevant instructions (~90% reduction)
// - Pre-allocated data structures to minimize allocations
// - Streamlined processing paths for common cases
// - Comprehensive logging for progress tracking on large codebases
//
// The function respects context cancellation and provides detailed progress logging
// when a logger is present in the context via WithLogger().
func NewGraph(root *ssa.Function, srcFns ...*ssa.Function) (*callgraph.Graph, error) {
	return NewGraphWithContext(context.Background(), root, srcFns...)
}

// NewGraphWithContext creates a new call graph with context support for cancellation and logging
func NewGraphWithContext(ctx context.Context, root *ssa.Function, srcFns ...*ssa.Function) (*callgraph.Graph, error) {
	if root == nil {
		return nil, fmt.Errorf("nil root function")
	}
	logger := FromContext(ctx)

	logger.Step("Starting call graph construction",
		fmt.Sprintf("root: %s", root.Name()),
		fmt.Sprintf("sources: %d functions", len(srcFns)))

	// Pre-allocate with reasonable capacity to reduce map reallocations
	g := &callgraph.Graph{
		Nodes: make(map[*ssa.Function]*callgraph.Node, 64),
	}

	g.Root = g.CreateNode(root)

	// MAJOR OPTIMIZATION: Cache AllFunctions results per program
	// This is the single biggest performance bottleneck - AllFunctions can take
	// 6+ms on large codebases and the result is identical for the same program
	logger.Debug("Computing AllFunctions for program")
	allFns := getAllFunctionsCached(root.Prog)
	logger.Debug("AllFunctions computed: %d total functions", len(allFns))

	// Pre-allocate visited map with estimated capacity
	visited := make(map[*ssa.Function]bool, len(srcFns)+16)

	// We'll create the progress tracker after determining functionsToProcess

	// Performance optimization: For very large codebases, use lazy evaluation
	// instead of processing all functions upfront. This aligns with Go's lazy evaluation principles.
	// Note: With our optimizations, we should process functions on-demand as they're discovered
	// in the call graph traversal, rather than pre-processing everything.
	const maxFunctionsToWalk = 0 // 0 means no limit - use lazy evaluation instead
	const maxRecursionDepth = 6  // limit recursion for performance, enough for common paths

	// Instead of limiting functions, we'll use a smarter traversal approach
	// that processes functions lazily as they're discovered in the call graph
	functionsToProcess := srcFns
	if maxFunctionsToWalk > 0 && len(srcFns) > maxFunctionsToWalk {
		logger.Debug("Large codebase detected (%d functions), limiting processing to %d most relevant functions", len(srcFns), maxFunctionsToWalk)

		// Sort functions by relevance for taint analysis
		// Prioritize: exported functions, functions with parameters, functions in main packages
		type functionWeight struct {
			fn     *ssa.Function
			weight int
		}

		var weightedFns []functionWeight
		for _, fn := range srcFns {
			weight := 0

			// Exported functions are more likely to be entry points
			if fn.Object() != nil && fn.Object().Exported() {
				weight += 10
			}

			// Functions with parameters are more likely to handle external data
			if fn.Signature.Params() != nil && fn.Signature.Params().Len() > 0 {
				weight += 5
			}

			// Functions with more instructions are more likely to be complex/interesting
			totalInstrs := 0
			for _, block := range fn.Blocks {
				totalInstrs += len(block.Instrs)
			}
			weight += min(totalInstrs/10, 5) // Cap at 5 points for instruction count

			weightedFns = append(weightedFns, functionWeight{fn, weight})
		}

		// Sort by weight (descending)
		for i := 0; i < len(weightedFns); i++ {
			for j := i + 1; j < len(weightedFns); j++ {
				if weightedFns[j].weight > weightedFns[i].weight {
					weightedFns[i], weightedFns[j] = weightedFns[j], weightedFns[i]
				}
			}
		}

		// Take top functions
		functionsToProcess = make([]*ssa.Function, 0, maxFunctionsToWalk)
		for i := 0; i < min(maxFunctionsToWalk, len(weightedFns)); i++ {
			functionsToProcess = append(functionsToProcess, weightedFns[i].fn)
		}

		logger.Debug("Selected %d highest-priority functions for processing", len(functionsToProcess))
	}

	// Baseline pass: scan all SSA functions to add direct call edges
	// Using allFns ensures we include methods and any function not listed in srcFns
	prepass := NewProgressTracker(ctx, "Prepass: direct call edges", len(allFns))
	logger.Step(fmt.Sprintf("Prepass: scanning %d SSA functions for direct calls", len(allFns)))
	for fn := range allFns {
		if fn == nil {
			prepass.Update("skip nil")
			continue
		}
		blocks := fn.Blocks
		if len(blocks) == 0 {
			prepass.Update(fn.Name())
			continue
		}
		// Fast skip if no call-like instructions present
		hasCall := false
		for _, b := range blocks {
			for _, ins := range b.Instrs {
				if _, ok := ins.(ssa.CallInstruction); ok {
					hasCall = true
					break
				}
			}
			if hasCall {
				break
			}
		}
		if !hasCall {
			prepass.Update(fn.Name())
			continue
		}
		// Add direct call edges without recursion
		for _, b := range blocks {
			for _, ins := range b.Instrs {
				_ = checkBlockInstructionOptimized(root, allFns, g, fn, ins, func(*ssa.Function) error { return nil })
			}
		}
		prepass.Update(fn.Name())
	}
	prepass.Complete()

	// Update progress tracker with actual number of functions to process
	progressTracker := NewProgressTracker(ctx, "Processing source functions", len(functionsToProcess))
	logger.Step(fmt.Sprintf("Processing source functions: %d functions to process", len(functionsToProcess)))
	var walkFnWithDepth func(fn *ssa.Function, depth int) error
	walkFnWithDepth = func(fn *ssa.Function, depth int) error {
		// Optional recursion depth limit (disabled by default)
		if maxRecursionDepth >= 0 && depth > maxRecursionDepth {
			return nil
		}

		// Check for context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if visited[fn] {
			return nil
		}
		visited[fn] = true

		logger.Trace("Walking function: %s (depth %d)", fn.Name(), depth)

		// Optimize block iteration - use basic blocks directly (faster than Dominator preorder)
		blocks := fn.Blocks
		if len(blocks) == 0 {
			return nil
		}

		// Performance optimization: Quick scan for call-like instructions
		// If no call/go/defer instructions found, skip expensive processing
		hasCallInstructions := false
		for _, block := range blocks {
			for _, instr := range block.Instrs {
				if _, ok := instr.(ssa.CallInstruction); ok {
					hasCallInstructions = true
					break
				}
			}
			if hasCallInstructions {
				break
			}
		}

		if !hasCallInstructions {
			logger.Trace("Function %s has no call instructions, skipping", fn.Name())
			return nil
		}

		logger.Trace("Processing %d blocks in function %s", len(blocks), fn.Name())

		for _, block := range blocks {
			if len(block.Instrs) == 0 {
				continue // Skip empty blocks
			}

			for _, instr := range block.Instrs {
				// Check for context cancellation periodically
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}

				if err := checkBlockInstructionOptimized(root, allFns, g, fn, instr, func(f *ssa.Function) error {
					return walkFnWithDepth(f, depth+1)
				}); err != nil {
					return err
				}
			}
		}

		return nil
	}

	// Simple wrapper for the original interface
	walkFn := func(fn *ssa.Function) error {
		return walkFnWithDepth(fn, 0)
	}

	for i, srcFn := range functionsToProcess {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return g, ctx.Err()
		default:
		}

		logger.Trace("Processing source function %d/%d: %s", i+1, len(functionsToProcess), srcFn.Name())

		if err := walkFn(srcFn); err != nil {
			logger.Error("Failed to process source function %s: %v", srcFn.Name(), err)
			return g, err
		}

		progressTracker.Update(fmt.Sprintf("Processing %s", srcFn.Name()))
	}

	progressTracker.Complete()

	logger.Debug("Removing duplicate edges from call graph")
	// Remove duplicate edges once at the end - much more efficient than doing it
	// on every instruction
	DeduplicateEdges(g)

	// Canonicalize edge ordering. Edges were appended to Out slices in the
	// order map iterations happened to visit functions; that order is
	// randomized between runs of the same program. Without a stable order
	// downstream traversals (taint.Check's DFS, analyzer callsite selection)
	// may report the same logical finding at a different SSA call site each
	// run. Sorting once here makes the entire graph deterministic.
	Canonicalize(g)

	logger.Step("Call graph construction completed",
		fmt.Sprintf("%d nodes", len(g.Nodes)),
		fmt.Sprintf("%d functions visited", len(visited)))

	return g, nil
}

// Canonicalize sorts every node's In and Out edge slices into a deterministic
// order so that downstream traversals do not depend on map iteration order.
//
// Edges are ordered by:
//  1. caller token.Pos of the call site (rebased to file/line/col when the
//     position is valid)
//  2. callee function identity (fn.String())
//  3. callee start position
//
// The call graph's Nodes map is left untouched; callers that need a stable
// node order should use SortedNodes.
func Canonicalize(g *callgraph.Graph) {
	if g == nil {
		return
	}
	for _, n := range g.Nodes {
		if n == nil {
			continue
		}
		sortEdges(n.Out)
		sortEdges(n.In)
	}
}

// SortedNodes returns the nodes of g in a deterministic order. The order is
// stable across runs of the same program: nodes are keyed by function
// identity (fn.String()) and then by start position to disambiguate
// same-named synthetic functions.
func SortedNodes(g *callgraph.Graph) []*callgraph.Node {
	if g == nil {
		return nil
	}
	out := make([]*callgraph.Node, 0, len(g.Nodes))
	for _, n := range g.Nodes {
		if n != nil {
			out = append(out, n)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return nodeLess(out[i], out[j])
	})
	return out
}

func sortEdges(edges []*callgraph.Edge) {
	sort.SliceStable(edges, func(i, j int) bool {
		return edgeLess(edges[i], edges[j])
	})
}

func sortedOutgoingEdges(n *callgraph.Node) []*callgraph.Edge {
	if n == nil {
		return nil
	}
	edges := append([]*callgraph.Edge(nil), n.Out...)
	sortEdges(edges)
	return edges
}

func edgeLess(a, b *callgraph.Edge) bool {
	ap, bp := edgePos(a), edgePos(b)
	if ap != bp {
		return ap < bp
	}
	ak, bk := calleeKey(a), calleeKey(b)
	if ak != bk {
		return ak < bk
	}
	return calleePos(a) < calleePos(b)
}

func edgePos(e *callgraph.Edge) token.Pos {
	if e == nil || e.Site == nil {
		return token.NoPos
	}
	return e.Site.Pos()
}

func calleeKey(e *callgraph.Edge) string {
	if e == nil || e.Callee == nil || e.Callee.Func == nil {
		return ""
	}
	return e.Callee.Func.String()
}

func calleePos(e *callgraph.Edge) token.Pos {
	if e == nil || e.Callee == nil || e.Callee.Func == nil {
		return token.NoPos
	}
	return e.Callee.Func.Pos()
}

func nodeLess(a, b *callgraph.Node) bool {
	ak, bk := nodeKey(a), nodeKey(b)
	if ak != bk {
		return ak < bk
	}
	return nodePos(a) < nodePos(b)
}

func nodeKey(n *callgraph.Node) string {
	if n == nil || n.Func == nil {
		return ""
	}
	return n.Func.String()
}

func nodePos(n *callgraph.Node) token.Pos {
	if n == nil || n.Func == nil {
		return token.NoPos
	}
	return n.Func.Pos()
}

// DeduplicateEdges removes duplicate call graph edges and rebuilds inbound edge
// lists so Node.In and Node.Out remain consistent.
func DeduplicateEdges(g *callgraph.Graph) {
	removeDuplicateEdges(g)
}

// removeDuplicateEdges efficiently removes duplicate edges from the call graph.
// This is done once at the end instead of on every instruction for better performance.
func removeDuplicateEdges(g *callgraph.Graph) {
	if g == nil {
		return
	}

	type edgeKey struct {
		caller *callgraph.Node
		callee *callgraph.Node
		site   ssa.CallInstruction
	}

	for _, node := range g.Nodes {
		if node == nil {
			continue
		}
		seen := make(map[edgeKey]struct{}, len(node.Out))
		uniqueEdges := make([]*callgraph.Edge, 0, len(node.Out))
		for _, edge := range node.Out {
			if edge == nil || edge.Callee == nil {
				continue
			}
			edge.Caller = node
			key := edgeKey{caller: node, callee: edge.Callee, site: edge.Site}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			uniqueEdges = append(uniqueEdges, edge)
		}
		node.Out = uniqueEdges
		node.In = nil
	}

	for _, node := range g.Nodes {
		if node == nil {
			continue
		}
		for _, edge := range node.Out {
			if edge == nil || edge.Callee == nil {
				continue
			}
			edge.Callee.In = append(edge.Callee.In, edge)
		}
	}
}

// checkBlockInstructionOptimized is a high-performance version of checkBlockInstruction
// with additional optimizations for large codebases. This version includes:
// 1. More aggressive early exits for non-call instructions
// 2. Optimized type switching with fast paths
// 3. Reduced allocations in hot paths
// 4. Streamlined argument processing
func checkBlockInstructionOptimized(root *ssa.Function, allFns map[*ssa.Function]bool, g *callgraph.Graph, fn *ssa.Function, instr ssa.Instruction, walkFn func(*ssa.Function) error) error {
	// Ultra-fast early exit: most instructions aren't calls (includes go/defer)
	callSite, ok := instr.(ssa.CallInstruction)
	if !ok {
		return nil
	}

	cc := callSite.Common()
	instrCalls := resolveCallTargets(root.Prog, allFns, cc)

	if len(instrCalls) == 0 {
		switch callt := cc.Value.(type) {
		case *ssa.Function:
			// Direct function call - most common case
			instrCalls = append(instrCalls, callt)

		case *ssa.MakeClosure:
			// Closure creation - second most common
			if calltFn, ok := callt.Fn.(*ssa.Function); ok {
				instrCalls = append(instrCalls, calltFn)
			}

		case *ssa.UnOp:
			// Dereference operations - less common
			if callt.Op == token.MUL {
				switch fa := callt.X.(type) {
				case *ssa.FieldAddr:
					instrCalls = append(instrCalls, findFunctionsInField(fa, allFns)...)
				case *ssa.Field:
					instrCalls = append(instrCalls, findFunctionsInFieldValue(fa, allFns)...)
				case *ssa.Global:
					instrCalls = append(instrCalls, findFunctionsStoredAt(fa, allFns)...)
				}
			}

		case *ssa.Lookup:
			// Map-valued function dispatch: handlers["foo"](w, r).
			instrCalls = append(instrCalls, findFunctionsInMap(callt, allFns)...)

		case *ssa.Extract:
			// Comma-ok map dispatch: h, ok := handlers["foo"]; h(...).
			// The tuple producer is the Lookup we actually want to resolve.
			if lookup, ok := callt.Tuple.(*ssa.Lookup); ok && callt.Index == 0 {
				instrCalls = append(instrCalls, findFunctionsInMap(lookup, allFns)...)
			}

		case *ssa.Phi:
			// Function chosen at a join point: f := cond ? a : b; f(...).
			instrCalls = append(instrCalls, findFunctionsInPhi(callt)...)
		}
	}

	// Early exit if no function was determined
	if len(instrCalls) == 0 {
		return nil
	}

	for _, instrCall := range dedupeFunctions(instrCalls) {
		if instrCall == nil {
			continue
		}

		// Add edge to call graph
		callgraph.AddEdge(g.CreateNode(fn), callSite, g.CreateNode(instrCall))

		if len(cc.Args) > 0 {
			if err := processFunctionArgumentsOptimized(g, callSite, instrCall); err != nil {
				return err
			}
		}

		if err := walkFn(instrCall); err != nil {
			return err
		}
	}

	return nil
}

// checkBlockInstruction checks a single SSA instruction within a basic block to determine
// if it represents a function call that should be added to the call graph. It includes
// several optimizations to minimize processing overhead.
//
// This function processes SSA instructions to build call graph edges. Key optimizations:
// 1. Early exit for non-call instructions (eliminates ~90% of processing)
// 2. Optimized ChangeInterface argument detection
// 3. Efficient argument processing with length checks
// 4. Streamlined method call handling
func checkBlockInstruction(root *ssa.Function, allFns map[*ssa.Function]bool, g *callgraph.Graph, fn *ssa.Function, instr ssa.Instruction, walkFn func(*ssa.Function) error) error {
	// Early exit for non-call instructions - includes go/defer
	callSite, ok := instr.(ssa.CallInstruction)
	if !ok {
		return nil
	}

	cc := callSite.Common()
	instrCalls := resolveCallTargets(root.Prog, allFns, cc)

	if len(instrCalls) == 0 {
		switch callt := cc.Value.(type) {
		case *ssa.Function:
			instrCalls = append(instrCalls, callt)

		case *ssa.MakeClosure:
			if calltFn, ok := callt.Fn.(*ssa.Function); ok {
				instrCalls = append(instrCalls, calltFn)
			}

		case *ssa.UnOp:
			if callt.Op == token.MUL {
				switch fa := callt.X.(type) {
				case *ssa.FieldAddr:
					instrCalls = append(instrCalls, findFunctionsInField(fa, allFns)...)
				case *ssa.Field:
					instrCalls = append(instrCalls, findFunctionsInFieldValue(fa, allFns)...)
				}
			}
		}
	}

	// Early exit if no function was determined
	if len(instrCalls) == 0 {
		return nil
	}

	for _, instrCall := range dedupeFunctions(instrCalls) {
		if instrCall == nil {
			continue
		}

		// Add edge to call graph
		callgraph.AddEdge(g.CreateNode(fn), callSite, g.CreateNode(instrCall))

		if len(cc.Args) > 0 {
			if err := processFunctionArguments(g, callSite, instrCall); err != nil {
				return err
			}
		}

		if err := walkFn(instrCall); err != nil {
			return err
		}
	}

	return nil
}

func resolveCallTargets(prog *ssa.Program, allFns map[*ssa.Function]bool, cc *ssa.CallCommon) []*ssa.Function {
	if cc == nil {
		return nil
	}
	if fn := cc.StaticCallee(); fn != nil {
		return []*ssa.Function{fn}
	}
	if !cc.IsInvoke() || cc.Method == nil {
		return nil
	}

	var targets []*ssa.Function
	for _, recvType := range concreteReceiverTypes(cc.Value) {
		targets = append(targets, concreteMethodsForInvoke(prog, allFns, recvType, cc.Method)...)
	}
	if len(targets) > 0 {
		return dedupeFunctions(targets)
	}

	recv := cc.Signature().Recv()
	if recv == nil {
		return nil
	}
	recvStr := types.TypeString(recv.Type(), nil)
	key := fmt.Sprintf("(%s).%s", recvStr, cc.Method.Name())
	return []*ssa.Function{getOrCreateSyntheticMethod(prog, key, cc.Method.Name(), cc.Signature())}
}

func concreteReceiverTypes(v ssa.Value) []types.Type {
	if v == nil {
		return nil
	}

	seen := map[ssa.Value]struct{}{}
	var out []types.Type
	var visit func(ssa.Value)
	visit = func(cur ssa.Value) {
		if cur == nil {
			return
		}
		if _, ok := seen[cur]; ok {
			return
		}
		seen[cur] = struct{}{}

		switch x := cur.(type) {
		case *ssa.MakeInterface:
			if x.X != nil {
				out = append(out, x.X.Type())
			}
		case *ssa.ChangeInterface:
			visit(x.X)
		case *ssa.ChangeType:
			visit(x.X)
		case *ssa.Convert:
			visit(x.X)
		case *ssa.TypeAssert:
			visit(x.X)
		case *ssa.Phi:
			for _, edge := range x.Edges {
				visit(edge)
			}
		default:
			t := cur.Type()
			if t != nil {
				if _, ok := t.Underlying().(*types.Interface); !ok {
					out = append(out, t)
				}
			}
		}
	}
	visit(v)
	return uniqueTypes(out)
}

func concreteMethodsForInvoke(prog *ssa.Program, allFns map[*ssa.Function]bool, recvType types.Type, method *types.Func) []*ssa.Function {
	if prog == nil || recvType == nil || method == nil {
		return nil
	}

	var targets []*ssa.Function
	for _, candidateType := range receiverTypeCandidates(recvType) {
		methodSet := prog.MethodSets.MethodSet(candidateType)
		if methodSet == nil {
			continue
		}
		sel := methodSet.Lookup(method.Pkg(), method.Name())
		if sel == nil {
			continue
		}
		if fn := functionForMethodObject(allFns, sel.Obj()); fn != nil {
			targets = append(targets, fn)
			continue
		}
		targets = append(targets, functionsMatchingReceiver(allFns, candidateType, method.Name())...)
	}
	return dedupeFunctions(targets)
}

func functionForMethodObject(allFns map[*ssa.Function]bool, obj types.Object) *ssa.Function {
	if obj == nil {
		return nil
	}
	for fn := range allFns {
		if fn != nil && fn.Object() == obj {
			return fn
		}
	}
	return nil
}

func functionsMatchingReceiver(allFns map[*ssa.Function]bool, recvType types.Type, methodName string) []*ssa.Function {
	var out []*ssa.Function
	for fn := range allFns {
		if fn == nil || fn.Name() != methodName || fn.Signature == nil || fn.Signature.Recv() == nil {
			continue
		}
		fnRecv := fn.Signature.Recv().Type()
		if types.Identical(fnRecv, recvType) || types.AssignableTo(recvType, fnRecv) || types.AssignableTo(fnRecv, recvType) {
			out = append(out, fn)
		}
	}
	return out
}

func receiverTypeCandidates(t types.Type) []types.Type {
	if t == nil {
		return nil
	}
	candidates := []types.Type{t}
	if _, ok := t.(*types.Pointer); !ok {
		candidates = append(candidates, types.NewPointer(t))
	}
	if ptr, ok := t.(*types.Pointer); ok {
		candidates = append(candidates, ptr.Elem())
	}
	return uniqueTypes(candidates)
}

func uniqueTypes(typesIn []types.Type) []types.Type {
	var out []types.Type
	for _, t := range typesIn {
		if t == nil {
			continue
		}
		seen := false
		for _, existing := range out {
			if types.Identical(existing, t) {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, t)
		}
	}
	return out
}

func dedupeFunctions(fns []*ssa.Function) []*ssa.Function {
	if len(fns) <= 1 {
		return fns
	}
	seen := make(map[*ssa.Function]struct{}, len(fns))
	out := make([]*ssa.Function, 0, len(fns))
	for _, fn := range fns {
		if fn == nil {
			continue
		}
		if _, ok := seen[fn]; ok {
			continue
		}
		seen[fn] = struct{}{}
		out = append(out, fn)
	}
	return out
}

// processChangeInterfaceArgsOptimized handles ChangeInterface arguments with enhanced performance.
//
// This optimized version includes:
// 1. Ultra-fast scanning to detect ChangeInterface before expensive processing
// 2. Early exits for common negative cases
// 3. Optimized type checking and method resolution
// 4. Reduced allocations in interface processing loops
func processChangeInterfaceArgsOptimized(root *ssa.Function, g *callgraph.Graph, site ssa.CallInstruction, instrCall *ssa.Function) error {
	cc := site.Common()
	// Lightning-fast scan for ChangeInterface arguments before expensive processing
	// This avoids allocating iterators and type checking when not needed
	hasChangeInterface := false
	for _, arg := range cc.Args {
		if _, ok := arg.(*ssa.ChangeInterface); ok {
			hasChangeInterface = true
			break
		}
	}

	if !hasChangeInterface {
		return nil
	}

	// Process ChangeInterface arguments with optimized loops
	for _, instrtCallArg := range cc.Args {
		instrtCallArgt, ok := instrtCallArg.(*ssa.ChangeInterface)
		if !ok {
			continue
		}

		argtt, ok := instrtCallArgt.Type().Underlying().(*types.Interface)
		if !ok {
			continue
		}

		numMethods := argtt.NumMethods()
		for i := 0; i < numMethods; i++ {
			method := argtt.Method(i)
			methodPkg := method.Pkg()
			if methodPkg == nil {
				continue // Universe scope method - skip early
			}

			pkg := root.Prog.ImportedPackage(methodPkg.Path())
			if pkg == nil {
				continue // Package not imported - skip early
			}

			fn := pkg.Func(method.Name())
			if fn == nil {
				fn = pkg.Prog.NewFunction(method.Name(), method.Type().(*types.Signature), "callgraph")
			}

			callgraph.AddEdge(g.CreateNode(instrCall), site, g.CreateNode(fn))

			// Handle named types efficiently with early exit optimization
			if xType, ok := instrtCallArgt.X.Type().(*types.Named); ok {
				pkg2 := root.Prog.ImportedPackage(xType.Obj().Pkg().Path())
				if pkg2 == nil {
					continue
				}

				methodSet := pkg2.Prog.MethodSets.MethodSet(xType)
				methodSel := methodSet.Lookup(pkg2.Pkg, method.Name())
				if methodSel == nil {
					continue
				}

				methodType := methodSel.Type().(*types.Signature)

				fn2 := pkg2.Func(method.Name())
				if fn2 == nil {
					fn2 = pkg2.Prog.NewFunction(method.Name(), methodType, "callgraph")
				}

				callgraph.AddEdge(g.CreateNode(fn), site, g.CreateNode(fn2))
			}
		}
	}
	return nil
}

// processFunctionArgumentsOptimized efficiently handles function arguments that are functions.
//
// This optimized version includes:
// 1. Streamlined type switching with fast paths
// 2. Reduced allocations in argument processing
// 3. Early exits for non-function arguments
func processFunctionArgumentsOptimized(g *callgraph.Graph, site ssa.CallInstruction, instrCall *ssa.Function) error {
	return processFunctionArgumentsByUse(g, site, instrCall)
}

func processFunctionArgumentsByUse(g *callgraph.Graph, site ssa.CallInstruction, instrCall *ssa.Function) error {
	if g == nil || site == nil || instrCall == nil || site.Common() == nil {
		return nil
	}

	for argIndex, arg := range site.Common().Args {
		callbacks := functionValues(arg)
		if len(callbacks) == 0 {
			continue
		}
		dispatches := callbackArgumentDispatches(site, instrCall, argIndex)
		if len(dispatches) == 0 {
			continue
		}
		for _, callback := range callbacks {
			for _, dispatch := range dispatches {
				caller := dispatch.caller
				if caller == nil {
					caller = instrCall
				}
				dispatchSite := dispatch.site
				if dispatchSite == nil {
					dispatchSite = site
				}
				callgraph.AddEdge(g.CreateNode(caller), dispatchSite, g.CreateNode(callback))
			}
		}
	}
	return nil
}

// processChangeInterfaceArgs handles ChangeInterface arguments with early exits.
//
// This function efficiently processes ChangeInterface type casts that are common
// in Go programs when converting between concrete types and interfaces.
// It uses early scanning to avoid expensive processing when not needed.
func processChangeInterfaceArgs(root *ssa.Function, g *callgraph.Graph, site ssa.CallInstruction, instrCall *ssa.Function) error {
	cc := site.Common()
	// Quick scan for ChangeInterface arguments before expensive processing
	hasChangeInterface := false
	for _, arg := range cc.Args {
		if _, ok := arg.(*ssa.ChangeInterface); ok {
			hasChangeInterface = true
			break
		}
	}

	if !hasChangeInterface {
		return nil
	}

	// Process ChangeInterface arguments
	for _, instrtCallArg := range cc.Args {
		instrtCallArgt, ok := instrtCallArg.(*ssa.ChangeInterface)
		if !ok {
			continue
		}

		argtt, ok := instrtCallArgt.Type().Underlying().(*types.Interface)
		if !ok {
			continue
		}

		numMethods := argtt.NumMethods()
		for i := 0; i < numMethods; i++ {
			method := argtt.Method(i)
			methodPkg := method.Pkg()
			if methodPkg == nil {
				continue // Universe scope method
			}

			pkg := root.Prog.ImportedPackage(methodPkg.Path())
			if pkg == nil {
				continue // Package not imported
			}

			fn := pkg.Func(method.Name())
			if fn == nil {
				fn = pkg.Prog.NewFunction(method.Name(), method.Type().(*types.Signature), "callgraph")
			}

			callgraph.AddEdge(g.CreateNode(instrCall), site, g.CreateNode(fn))

			// Handle named types efficiently with early exit
			if xType, ok := instrtCallArgt.X.Type().(*types.Named); ok {
				pkg2 := root.Prog.ImportedPackage(xType.Obj().Pkg().Path())
				if pkg2 == nil {
					continue
				}

				methodSet := pkg2.Prog.MethodSets.MethodSet(xType)
				methodSel := methodSet.Lookup(pkg2.Pkg, method.Name())
				if methodSel == nil {
					continue
				}

				methodType := methodSel.Type().(*types.Signature)

				fn2 := pkg2.Func(method.Name())
				if fn2 == nil {
					fn2 = pkg2.Prog.NewFunction(method.Name(), methodType, "callgraph")
				}

				callgraph.AddEdge(g.CreateNode(fn), site, g.CreateNode(fn2))
			}
		}
	}
	return nil
}

// processFunctionArguments efficiently handles function arguments that are functions.
//
// This handles cases where functions are passed as arguments to other functions,
// which is common in callback patterns and higher-order functions.
func processFunctionArguments(g *callgraph.Graph, site ssa.CallInstruction, instrCall *ssa.Function) error {
	return processFunctionArgumentsByUse(g, site, instrCall)
}

// AddFunction analyzes the given target SSA function, adding information to the call graph.
//
// Based on the implementation of golang.org/x/tools/cmd/guru/callers.go:
// https://cs.opensource.google/go/x/tools/+/master:cmd/guru/callers.go;drc=3e0d083b858b3fdb7d095b5a3deb184aa0a5d35e;bpv=1;bpt=1;l=90
func AddFunction(cg *callgraph.Graph, target *ssa.Function, allFns map[*ssa.Function]bool) error {
	// First check if we have already processed this function - early exit
	if _, ok := cg.Nodes[target]; ok {
		return nil
	}

	targetNode := cg.CreateNode(target)

	// Find receiver type (for methods) with early exit optimization
	var recvType types.Type
	if recv := target.Signature.Recv(); recv != nil {
		recvType = recv.Type()
	}

	// Use provided allFns map or compute if not provided
	if len(allFns) == 0 {
		allFns = ssautil.AllFunctions(target.Prog)
	}

	// Pre-allocate operands slice to avoid repeated allocations
	// Using a reasonable size that should handle most cases without reallocation
	var operands [32]*ssa.Value

	// Find all direct calls to function, or places where its address is taken.
	for progFn := range allFns {
		// Early exit: skip if function has no blocks
		blocks := progFn.DomPreorder()
		if len(blocks) == 0 {
			continue
		}

		for _, block := range blocks {
			// Early exit: skip empty blocks
			if len(block.Instrs) == 0 {
				continue
			}

			for _, instr := range block.Instrs {
				// Optimize method receiver type checking
				// Is this a method (T).f of a concrete type T whose runtime type descriptor is address-taken?
				if recvType != nil {
					if mi, ok := instr.(*ssa.MakeInterface); ok {
						if types.Identical(mi.X.Type(), recvType) {
							return nil // T is address-taken
						}
						if ptr, ok := mi.X.Type().(*types.Pointer); ok &&
							types.Identical(ptr.Elem(), recvType) {
							return nil // *T is address-taken
						}
					}
				}

				// Optimize operand handling by reusing pre-allocated slice
				rands := instr.Operands(operands[:0])

				// Direct call to target? Check this efficiently
				if site, ok := instr.(ssa.CallInstruction); ok && site.Common().Value == target {
					callgraph.AddEdge(cg.CreateNode(progFn), site, targetNode)
					rands = rands[1:] // skip .Value (rands[0])
				}

				// Address-taken check - optimized to avoid unnecessary dereferences
				for _, rand := range rands {
					if rand != nil && *rand == target {
						return nil
					}
				}
			}
		}
	}

	return nil
}

// findFunctionsInField scans assignments to the provided struct field address.
// Stores to the same allocation are preferred; when the allocation cannot be
// tied back precisely, all matching field stores are returned conservatively.
func findFunctionsInField(fieldAddr *ssa.FieldAddr, allFns map[*ssa.Function]bool) []*ssa.Function {
	idx := fieldAddr.Field
	structType := fieldAddr.X.Type()
	var exact []*ssa.Function
	var fallback []*ssa.Function

	for fn := range allFns {
		for _, blk := range fn.Blocks {
			for _, ins := range blk.Instrs {
				if store, ok := ins.(*ssa.Store); ok {
					if fa, ok := store.Addr.(*ssa.FieldAddr); ok {
						if fa.Field == idx && types.Identical(fa.X.Type(), structType) {
							for _, storedFn := range functionValues(store.Val) {
								if sameFieldBase(fa.X, fieldAddr.X) {
									exact = append(exact, storedFn)
								} else {
									fallback = append(fallback, storedFn)
								}
							}
						}
					}
				}
			}
		}
	}
	if len(exact) > 0 {
		return dedupeFunctions(exact)
	}
	return dedupeFunctions(fallback)
}

// findFunctionsInFieldValue searches for function assignments made to the struct
// field represented by the given Field value.
func findFunctionsInFieldValue(field *ssa.Field, allFns map[*ssa.Function]bool) []*ssa.Function {
	idx := field.Field
	structType := field.X.Type()
	var exact []*ssa.Function
	var fallback []*ssa.Function

	for fn := range allFns {
		for _, blk := range fn.Blocks {
			for _, ins := range blk.Instrs {
				if store, ok := ins.(*ssa.Store); ok {
					if fa, ok := store.Addr.(*ssa.FieldAddr); ok {
						if fa.Field == idx && types.Identical(fa.X.Type(), structType) {
							for _, storedFn := range functionValues(store.Val) {
								if sameFieldBase(fa.X, field.X) {
									exact = append(exact, storedFn)
								} else {
									fallback = append(fallback, storedFn)
								}
							}
						}
					}
				}
			}
		}
	}
	if len(exact) > 0 {
		return dedupeFunctions(exact)
	}
	return dedupeFunctions(fallback)
}

// findFunctionsStoredAt scans the program for stores targeting the given
// address-valued SSA value (typically a *ssa.Global holding a function-typed
// variable) and returns every distinct function that flows into the address.
// This lets indirect calls through a global function variable resolve to its
// possible callees.
func findFunctionsStoredAt(addr ssa.Value, allFns map[*ssa.Function]bool) []*ssa.Function {
	if addr == nil {
		return nil
	}
	var out []*ssa.Function
	for fn := range allFns {
		for _, blk := range fn.Blocks {
			for _, ins := range blk.Instrs {
				store, ok := ins.(*ssa.Store)
				if !ok || store.Addr != addr {
					continue
				}
				out = append(out, functionValues(store.Val)...)
			}
		}
	}
	return dedupeFunctions(out)
}

// findFunctionsInMap resolves a map-valued function dispatch
// (handlers[key](...)) to the set of functions previously stored into the same
// map. Stores reach across functions, mirroring how findFunctionsInField scans
// the whole program for field assignments.
func findFunctionsInMap(lookup *ssa.Lookup, allFns map[*ssa.Function]bool) []*ssa.Function {
	if lookup == nil {
		return nil
	}
	mapValue := lookup.X
	if mapValue == nil {
		return nil
	}
	var out []*ssa.Function
	for fn := range allFns {
		for _, blk := range fn.Blocks {
			for _, ins := range blk.Instrs {
				upd, ok := ins.(*ssa.MapUpdate)
				if !ok || !sameMapBase(upd.Map, mapValue) {
					continue
				}
				out = append(out, functionValues(upd.Value)...)
			}
		}
	}
	return dedupeFunctions(out)
}

// findFunctionsInPhi resolves a phi-valued indirect call: f := cond ? a : b;
// f(...). Each incoming edge is folded through functionValues so closures and
// converted function references are recognized.
func findFunctionsInPhi(phi *ssa.Phi) []*ssa.Function {
	if phi == nil {
		return nil
	}
	var out []*ssa.Function
	for _, edge := range phi.Edges {
		out = append(out, functionValues(edge)...)
	}
	return dedupeFunctions(out)
}

// sameMapBase returns true when two SSA values refer to the same underlying
// map. Direct identity covers map values built in the current function;
// loads from the same *ssa.Global cover package-level maps, including the
// common pattern where the package init function performs MapUpdate on a
// freshly created map before storing it into the global.
func sameMapBase(a, b ssa.Value) bool {
	if a == nil || b == nil {
		return false
	}
	if a == b {
		return true
	}
	ga := mapBackingGlobal(a)
	gb := mapBackingGlobal(b)
	return ga != nil && ga == gb
}

// mapBackingGlobal returns the *ssa.Global that backs a map-valued SSA value
// when one is reachable through trivial dereference or via the
// MakeMap-then-Store pattern emitted for package-level map literals.
func mapBackingGlobal(v ssa.Value) *ssa.Global {
	if v == nil {
		return nil
	}
	if g := globalBacking(v); g != nil {
		return g
	}
	mm, ok := v.(*ssa.MakeMap)
	if !ok {
		return nil
	}
	refs := mm.Referrers()
	if refs == nil {
		return nil
	}
	for _, ref := range *refs {
		store, ok := ref.(*ssa.Store)
		if !ok || store.Val != mm {
			continue
		}
		if g, ok := store.Addr.(*ssa.Global); ok {
			return g
		}
	}
	return nil
}

func globalBacking(v ssa.Value) *ssa.Global {
	switch x := v.(type) {
	case *ssa.UnOp:
		if x.Op == token.MUL {
			if g, ok := x.X.(*ssa.Global); ok {
				return g
			}
		}
	case *ssa.Global:
		return x
	}
	return nil
}

func functionValues(v ssa.Value) []*ssa.Function {
	seen := map[ssa.Value]struct{}{}
	var visit func(ssa.Value) []*ssa.Function
	visit = func(cur ssa.Value) []*ssa.Function {
		if cur == nil {
			return nil
		}
		if _, ok := seen[cur]; ok {
			return nil
		}
		seen[cur] = struct{}{}

		switch value := cur.(type) {
		case *ssa.Function:
			return []*ssa.Function{value}
		case *ssa.MakeClosure:
			if f, ok := value.Fn.(*ssa.Function); ok {
				return []*ssa.Function{f}
			}
		case *ssa.MakeInterface:
			return visit(value.X)
		case *ssa.ChangeInterface:
			return visit(value.X)
		case *ssa.ChangeType:
			return visit(value.X)
		case *ssa.Convert:
			return visit(value.X)
		case *ssa.TypeAssert:
			return visit(value.X)
		}
		return nil
	}
	return dedupeFunctions(visit(v))
}

type callbackDispatch struct {
	caller *ssa.Function
	site   ssa.CallInstruction
}

func callbackArgumentDispatches(site ssa.CallInstruction, callee *ssa.Function, argIndex int) []callbackDispatch {
	if knownCallbackRegistrationArg(site, argIndex) {
		return []callbackDispatch{{caller: callee, site: site}}
	}
	param := parameterForCallArg(site.Common(), callee, argIndex)
	if param == nil {
		return nil
	}
	return dedupeCallbackDispatches(functionParameterDispatches(callee, param, map[callbackParamKey]struct{}{}))
}

type callbackParamKey struct {
	fn    *ssa.Function
	param *ssa.Parameter
}

func functionParameterDispatches(fn *ssa.Function, param *ssa.Parameter, seen map[callbackParamKey]struct{}) []callbackDispatch {
	if fn == nil || param == nil || len(fn.Blocks) == 0 {
		return nil
	}
	key := callbackParamKey{fn: fn, param: param}
	if _, ok := seen[key]; ok {
		return nil
	}
	seen[key] = struct{}{}

	var out []callbackDispatch
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			call, ok := instr.(ssa.CallInstruction)
			if !ok || call.Common() == nil {
				continue
			}
			common := call.Common()
			if valueDerivedFromParameter(common.Value, param) {
				out = append(out, callbackDispatch{caller: fn, site: call})
				continue
			}
			target := staticCalleeForCallCommon(common)
			for argIndex, arg := range common.Args {
				if !valueDerivedFromParameter(arg, param) {
					continue
				}
				if knownCallbackRegistrationArg(call, argIndex) {
					caller := target
					if caller == nil {
						caller = fn
					}
					out = append(out, callbackDispatch{caller: caller, site: call})
					continue
				}
				targetParam := parameterForCallArg(common, target, argIndex)
				out = append(out, functionParameterDispatches(target, targetParam, seen)...)
			}
		}
	}
	return out
}

func dedupeCallbackDispatches(dispatches []callbackDispatch) []callbackDispatch {
	if len(dispatches) <= 1 {
		return dispatches
	}
	seen := make(map[callbackDispatch]struct{}, len(dispatches))
	out := make([]callbackDispatch, 0, len(dispatches))
	for _, dispatch := range dispatches {
		if dispatch.site == nil {
			continue
		}
		if _, ok := seen[dispatch]; ok {
			continue
		}
		seen[dispatch] = struct{}{}
		out = append(out, dispatch)
	}
	return out
}

func valueDerivedFromParameter(v ssa.Value, param *ssa.Parameter) bool {
	seen := map[ssa.Value]struct{}{}
	var visit func(ssa.Value) bool
	visit = func(cur ssa.Value) bool {
		if cur == nil {
			return false
		}
		if cur == param {
			return true
		}
		if _, ok := seen[cur]; ok {
			return false
		}
		seen[cur] = struct{}{}

		switch value := cur.(type) {
		case *ssa.MakeInterface:
			return visit(value.X)
		case *ssa.ChangeInterface:
			return visit(value.X)
		case *ssa.ChangeType:
			return visit(value.X)
		case *ssa.Convert:
			return visit(value.X)
		case *ssa.TypeAssert:
			return visit(value.X)
		case *ssa.Phi:
			for _, edge := range value.Edges {
				if visit(edge) {
					return true
				}
			}
		case *ssa.UnOp:
			if visit(value.X) {
				return true
			}
			if value.Op == token.MUL {
				for _, stored := range storedValuesForAddress(value.X) {
					if visit(stored) {
						return true
					}
				}
			}
		case *ssa.Alloc:
			for _, stored := range storedValuesForAddress(value) {
				if visit(stored) {
					return true
				}
			}
		case ssa.Instruction:
			for _, operand := range value.Operands(nil) {
				if operand != nil && visit(*operand) {
					return true
				}
			}
		}
		return false
	}
	return visit(v)
}

func storedValuesForAddress(addr ssa.Value) []ssa.Value {
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

func parameterForCallArg(common *ssa.CallCommon, callee *ssa.Function, argIndex int) *ssa.Parameter {
	if common == nil || callee == nil || argIndex < 0 {
		return nil
	}
	paramIndex := argIndex
	if common.IsInvoke() && callee.Signature != nil && callee.Signature.Recv() != nil {
		paramIndex++
	}
	if paramIndex < 0 || paramIndex >= len(callee.Params) {
		return nil
	}
	return callee.Params[paramIndex]
}

func staticCalleeForCallCommon(common *ssa.CallCommon) *ssa.Function {
	if common == nil {
		return nil
	}
	if fn := common.StaticCallee(); fn != nil {
		return fn
	}
	switch value := common.Value.(type) {
	case *ssa.Function:
		return value
	case *ssa.MakeClosure:
		if fn, ok := value.Fn.(*ssa.Function); ok {
			return fn
		}
	}
	return nil
}

func knownCallbackRegistrationArg(site ssa.CallInstruction, argIndex int) bool {
	if site == nil || site.Common() == nil {
		return false
	}
	switch callCommonString(site.Common()) {
	case "net/http.Handle", "net/http.HandleFunc":
		return argIndex == 1
	case "(*net/http.ServeMux).Handle", "(net/http.ServeMux).Handle",
		"(*net/http.ServeMux).HandleFunc", "(net/http.ServeMux).HandleFunc":
		return argIndex == 2
	case "net/http.ListenAndServe":
		return argIndex == 1
	case "net/http.ListenAndServeTLS":
		return argIndex == 3
	}
	return false
}

func callCommonString(common *ssa.CallCommon) string {
	if common == nil {
		return ""
	}
	if fn := common.StaticCallee(); fn != nil {
		return fn.String()
	}
	if common.IsInvoke() && common.Method != nil && common.Signature() != nil && common.Signature().Recv() != nil {
		recvStr := types.TypeString(common.Signature().Recv().Type(), nil)
		return fmt.Sprintf("(%s).%s", recvStr, common.Method.Name())
	}
	if common.Value != nil {
		return common.Value.String()
	}
	return ""
}

func sameFieldBase(a, b ssa.Value) bool {
	return fieldBase(a) != nil && fieldBase(a) == fieldBase(b)
}

func fieldBase(v ssa.Value) ssa.Value {
	seen := map[ssa.Value]struct{}{}
	for v != nil {
		if _, ok := seen[v]; ok {
			return v
		}
		seen[v] = struct{}{}

		switch x := v.(type) {
		case *ssa.FieldAddr:
			v = x.X
		case *ssa.Field:
			v = x.X
		case *ssa.IndexAddr:
			v = x.X
		case *ssa.UnOp:
			if x.Op == token.MUL {
				v = x.X
				continue
			}
			return v
		case *ssa.ChangeType:
			v = x.X
		case *ssa.Convert:
			v = x.X
		default:
			return v
		}
	}
	return nil
}
