package taint

import (
	"fmt"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	"github.com/picatz/taint/callgraphutil"
)

// findAllCallSitePaths finds all paths that end with a call to the specified sink function.
// Unlike PathsSearchCallTo which finds paths to the function node, this finds paths to
// individual call sites (edges) that call the function.
func findAllCallSitePaths(cg *callgraph.Graph, sinkFunc string) callgraphutil.Paths {
	return findAllSinkCallSitePaths(cg, exactSinkRule(sinkFunc))
}

func findAllSinkCallSitePaths(cg *callgraph.Graph, sink sinkRule) callgraphutil.Paths {
	if cg == nil || cg.Root == nil {
		return nil
	}

	var paths callgraphutil.Paths
	var stack callgraphutil.Path
	seen := make(map[*callgraph.Node]bool)

	var search func(*callgraph.Node)
	search = func(node *callgraph.Node) {
		if node == nil || seen[node] {
			return
		}
		seen[node] = true
		defer delete(seen, node)

		for _, edge := range node.Out {
			if edge == nil || edge.Callee == nil {
				continue
			}
			if sink.matchEdge != nil && sink.matchEdge(edge) {
				pathCopy := make(callgraphutil.Path, len(stack), len(stack)+1)
				copy(pathCopy, stack)
				pathCopy = append(pathCopy, edge)
				paths = append(paths, pathCopy)
			}
			stack = append(stack, edge)
			search(edge.Callee)
			stack = stack[:len(stack)-1]
		}
	}
	search(cg.Root)

	return paths
}

func edgeCallsSink(edge *callgraph.Edge, sinkFunc string) bool {
	if edge == nil {
		return false
	}
	if edge.Callee != nil && edge.Callee.Func != nil && functionMatchesSink(edge.Callee.Func, sinkFunc) {
		return true
	}
	if edge.Site == nil {
		return false
	}
	cc := edge.Site.Common()
	if cc == nil {
		return false
	}
	if fn := cc.StaticCallee(); fn != nil && functionMatchesSink(fn, sinkFunc) {
		return true
	}
	if cc.Value != nil && !cc.IsInvoke() {
		switch v := cc.Value.(type) {
		case *ssa.Function:
			if functionMatchesSink(v, sinkFunc) {
				return true
			}
		case *ssa.MakeClosure:
			if fn, ok := v.Fn.(*ssa.Function); ok && functionMatchesSink(fn, sinkFunc) {
				return true
			}
		}
	}
	if cc.IsInvoke() && cc.Method != nil && cc.Signature() != nil && cc.Signature().Recv() != nil {
		return methodSignatureMatchesSink(cc.Signature().Recv().Type(), cc.Method.Name(), sinkFunc)
	}
	return false
}

func functionMatchesSink(fn *ssa.Function, sinkFunc string) bool {
	if fn == nil {
		return false
	}
	if fn.String() == sinkFunc {
		return true
	}
	if sig := fn.Signature; sig != nil && sig.Recv() != nil {
		return methodSignatureMatchesSink(sig.Recv().Type(), fn.Name(), sinkFunc)
	}
	return false
}

func methodSignatureMatchesSink(recv types.Type, methodName, sinkFunc string) bool {
	recvStr := types.TypeString(recv, nil)
	methodSig := fmt.Sprintf("(%s).%s", recvStr, methodName)
	if methodSig == sinkFunc {
		return true
	}
	alt := strings.TrimPrefix(recvStr, "*")
	altSig := fmt.Sprintf("(%s).%s", alt, methodName)
	return altSig == sinkFunc
}

// Result is an individual finding from a taint check.
// It contains the path within the callgraph where the source
// found its way into the sink, along with the source and sink
// type information and SSA values.
type Result struct {
	// Path is the specific path within a callgraph
	// where the source founds its way into a sink.
	Path callgraphutil.Path

	// Source type information.
	SourceType string
	// Source SSA value.
	SourceValue ssa.Value

	// Sink information.
	SinkType string
	// Sink SSA value.
	SinkValue ssa.Value
}

// Results is a collection of unique findings from a taint check.
type Results []Result

// Check is the primary function users of this package will use.
//
// It returns a list of results from the callgraph, where any of the given
// sources found their way into any of the given sinks.
//
// Sources is a list of functions that return user-controlled values,
// such as HTTP request parameters. Sinks is a list of potentially dangerous
// functions that should not be called with user-controlled values.
//
//	Diagram
//	             ╭───────────────────────────────────────────────────────────────╮
//	             │                          ╭────────┬──────────────╮            │
//	             │                          ▼        │              │            │
//	╭───────╮    │ ╭───────────╮    ╭───────────────╮│   ╭──────────┴──────────╮ │
//	│ Check ├──▶ │ │ checkPath ├──▶ │ checkSSAValue ├┴─▶ │ checkSSAInstruction │ │
//	╰───────╯    │ ╰───────────╯    ╰───────────────╯    ╰─────────────────────╯ │
//	             ╰──────────────────────────────┬────────────────────────────────╯
//	                                            │
//	                                            ▼
//	                                       ╭─────────╮
//	                                       │ Results │
//	                                       ╰─────────╯
//
// This is a recursive algorithm that will traverse the callgraph to identify
// if any of the given sources were used to obtain the initial SSA value (v).
// We handle this value, depending on its type, where we "peel back" its
// references and relevant SSA instructions to determine if any of the given
// sinks were involved in the creation of the initial value.
func Check(cg *callgraph.Graph, sources Sources, sinks Sinks) Results {
	return CheckDetailed(cg, sources, sinks).Results()
}

// CheckDetailed runs taint analysis and returns diagnostics with ordered
// evidence traces. It is additive to Check; callers that only need the legacy
// result shape can continue to use Check.
func CheckDetailed(cg *callgraph.Graph, sources Sources, sinks Sinks, opts ...Option) Diagnostics {
	cfg := defaultCheckConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	rules := newRuleRegistry(sources, sinks, cfg)

	// Select the richest path per (sink callsite position, source type).
	bestByKey := make(map[string]Diagnostic)

	// For each sink given, identify the individual paths from
	// within the callgraph that those sinks can end up as
	// the final node path (the "sink path").
	for _, sink := range rules.sinkRules {
		// Find all call edges that call the sink function
		sinkPaths := findAllSinkCallSitePaths(cg, sink)

		for _, sinkPath := range sinkPaths {
			// Ensure the path isn't empty (which can happen?!).
			//
			//       are never empty. That's just silly.
			if sinkPath.Empty() {
				continue
			}

			// Check if the last edge (e.g. a SQL query) used any of the given
			// sources (e.g. user input in an HTTP request) to identify if it
			// was "tainted".
			trace := &traceRecorder{}
			tainted, src, tv := checkPathDetailed(sinkPath, rules, sink, trace)

			if tainted {
				lastEdge := sinkPath.Last()
				if lastEdge == nil || lastEdge.Site == nil || lastEdge.Callee == nil {
					continue
				}
				sinkPos := lastEdge.Site.Pos()
				key := fmt.Sprintf("%d|%s", sinkPos, src)
				result := Result{
					Path:        clonePath(sinkPath),
					SourceType:  src,
					SourceValue: tv,
					SinkType:    sink.id,
					SinkValue:   lastEdge.Site.Value(),
				}
				if lastEdge.Callee != nil && lastEdge.Callee.Func != nil {
					result.SinkType = lastEdge.Callee.Func.String()
				}
				candidate := Diagnostic{
					Result:   result,
					Evidence: buildDiagnosticEvidence(sinkPath, sink, result, trace.evidence),
				}
				// Prefer richer (longer) paths so parameter mapping across wrappers is preserved
				if prev, ok := bestByKey[key]; !ok || len(candidate.Result.Path) > len(prev.Result.Path) {
					bestByKey[key] = candidate
				}
			}
		}
	}

	// Drain the map into a slice in a deterministic order. Range-over-map
	// gives a fresh permutation each run; using sorted keys here makes the
	// subsequent stable sort idempotent under reordering of equal keys.
	out := make(Diagnostics, 0, len(bestByKey))
	for _, key := range sortedDiagnosticKeys(bestByKey) {
		out = append(out, bestByKey[key])
	}
	sort.SliceStable(out, func(i, j int) bool {
		left, right := out[i].Result, out[j].Result
		lp, rp := sinkValuePos(left), sinkValuePos(right)
		if lp != rp {
			return lp < rp
		}
		if left.SourceType != right.SourceType {
			return left.SourceType < right.SourceType
		}
		return left.SinkType < right.SinkType
	})
	return out
}

func sortedDiagnosticKeys(m map[string]Diagnostic) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sinkValuePos returns the source position of a Result's sink call. A nil
// SinkValue collapses to token.NoPos so the comparator stays total.
func sinkValuePos(r Result) token.Pos {
	if r.SinkValue == nil {
		return token.NoPos
	}
	return r.SinkValue.Pos()
}

// checkPath implements taint analysis that can be used to identify if the given
// callgraph path contains information from taintable sources (typically user input).
func checkPath(path callgraphutil.Path, sources Sources) (bool, string, ssa.Value) {
	rules := newRuleRegistry(sources, nil, defaultCheckConfig())
	return checkPathDetailed(path, rules, sinkRule{selectArgs: defaultSinkArguments}, nil)
}

func checkPathDetailed(path callgraphutil.Path, rules *ruleRegistry, sink sinkRule, trace *traceRecorder) (bool, string, ssa.Value) {
	// Ensure the path isn't empty (which can happen?!).
	if path.Empty() {
		return false, "", nil
	}

	last := path.Last()
	if last == nil || last.Site == nil {
		return false, "", nil
	}

	// Start at the sink call arguments. The sink call's result is usually
	// irrelevant; the security question is whether tainted values are passed
	// into the operation.
	args := defaultSinkArguments(last)
	if sink.selectArgs != nil {
		args = sink.selectArgs(last)
	}
	for _, arg := range args {
		if sanitizer, ok := rules.sanitizerForValue(arg); ok {
			trace.add(Evidence{
				Kind:    EvidenceSanitizerApplied,
				Message: "sink argument is sanitizer result",
				Rule:    sanitizer.id,
				Value:   arg,
				Edge:    last,
			})
			continue
		}
		if sanitizer, ok := rules.expressionContainsSanitizer(arg); ok {
			trace.add(Evidence{
				Kind:    EvidenceSanitizerRejected,
				Message: "sanitizer appears inside an expression that is not fully sanitized",
				Rule:    sanitizer.id,
				Value:   arg,
				Edge:    last,
			})
		}
		tainted, src, tv := checkSSAValue(path, rules.sources, arg, valueSet{})
		if tainted {
			if _, sanitized := rules.sanitizerForValue(tv); sanitized {
				continue
			}
			if _, ok := rules.expressionContainsSanitizer(arg); !ok {
				trace.add(Evidence{
					Kind:    EvidenceSanitizerRejected,
					Message: "no configured sanitizer matched sink argument",
					Value:   arg,
					Edge:    last,
				})
			}
			return true, src, tv
		}
	}
	if len(args) > 0 {
		return false, "", nil
	}

	if sanitizer, ok := rules.sanitizerForValue(last.Site.Value()); ok {
		trace.add(Evidence{
			Kind:    EvidenceSanitizerApplied,
			Message: "sink value is sanitizer result",
			Rule:    sanitizer.id,
			Value:   last.Site.Value(),
			Edge:    last,
		})
		return false, "", nil
	}

	tainted, src, tv := checkSSAValue(path, rules.sources, last.Site.Value(), valueSet{})
	if tainted {
		if _, sanitized := rules.sanitizerForValue(tv); sanitized {
			return false, "", nil
		}
		return true, src, tv
	}

	return false, "", nil
}

func buildDiagnosticEvidence(path callgraphutil.Path, sink sinkRule, result Result, sanitizerEvidence []Evidence) []Evidence {
	evidence := make([]Evidence, 0, len(path)*2+len(sanitizerEvidence)+2)
	evidence = append(evidence, Evidence{
		Kind:    EvidenceSourceMatch,
		Message: "value matched configured source",
		Rule:    result.SourceType,
		Value:   result.SourceValue,
	})

	for _, edge := range path {
		if edge == nil {
			evidence = append(evidence, Evidence{
				Kind:    EvidenceUnknown,
				Message: "path contains nil callgraph edge",
			})
			continue
		}
		if edge.Caller == nil || edge.Callee == nil || edge.Caller.Func == nil || edge.Callee.Func == nil {
			evidence = append(evidence, Evidence{
				Kind:    EvidenceUnknown,
				Message: "path contains partially resolved callgraph edge",
				Edge:    edge,
			})
		}
		if edge.Callee != nil && edge.Callee.Func != nil && edge.Callee.Func.Synthetic != "" {
			evidence = append(evidence, Evidence{
				Kind:     EvidenceUnknown,
				Message:  "call target uses synthetic modeling",
				Rule:     edge.Callee.Func.Synthetic,
				Edge:     edge,
				Function: edge.Callee.Func,
			})
		}
		if edge.Callee != nil && edge.Callee.Func != nil {
			evidence = append(evidence, Evidence{
				Kind:     EvidencePropagationStep,
				Message:  "taint path crosses callgraph edge",
				Edge:     edge,
				Function: edge.Callee.Func,
			})
		}
		if edge.Site == nil || edge.Site.Common() == nil {
			continue
		}
		common := edge.Site.Common()
		for _, entry := range parameterMappings(edge, common) {
			evidence = append(evidence, entry)
		}
	}

	evidence = append(evidence, sanitizerEvidence...)
	last := path.Last()
	evidence = append(evidence, Evidence{
		Kind:    EvidenceSinkMatch,
		Message: "callsite matched configured sink",
		Rule:    sink.id,
		Value:   result.SinkValue,
		Edge:    last,
	})
	return evidence
}

func parameterMappings(edge *callgraph.Edge, common *ssa.CallCommon) []Evidence {
	if edge == nil || edge.Callee == nil || edge.Callee.Func == nil || common == nil {
		return nil
	}
	params := edge.Callee.Func.Params
	args := common.Args
	if len(args) == 0 {
		return nil
	}
	if len(params) == 0 {
		out := make([]Evidence, 0, len(args))
		for i, arg := range args {
			if arg == nil {
				continue
			}
			out = append(out, Evidence{
				Kind:    EvidenceParameterMapping,
				Message: fmt.Sprintf("argument %d maps to unresolved callee parameter", i),
				Value:   arg,
				Edge:    edge,
			})
		}
		return out
	}
	limit := min(len(params), len(args))
	out := make([]Evidence, 0, limit)
	for i := 0; i < limit; i++ {
		if params[i] == nil || args[i] == nil {
			continue
		}
		out = append(out, Evidence{
			Kind:    EvidenceParameterMapping,
			Message: fmt.Sprintf("argument %d maps to parameter %s", i, params[i].Name()),
			Value:   args[i],
			Edge:    edge,
		})
	}
	return out
}

func clonePath(path callgraphutil.Path) callgraphutil.Path {
	if len(path) == 0 {
		return nil
	}
	out := make(callgraphutil.Path, len(path))
	copy(out, path)
	return out
}

// checkSSAValue implements the core taint analysis algorithm. It identifies
// if the given value "v" comes from any of the given sources (user input).
//
// It keeps track of nodes it has previously visted/checked, and recursively
// calls itself (or checkSSAInstruction) as nessecary.
//
// It returns true if the given SSA value is tained by any of the given sources.
func checkSSAValue(path callgraphutil.Path, sources Sources, v ssa.Value, visited valueSet) (bool, string, ssa.Value) {
	// First, check if this value has already been visited.
	//
	// If so, we can assume it is safe.
	if visited.includes(v) {
		return false, "", nil
	}

	// If it was not previously visited, we add it to the set
	// of visited values. This will prevent visting cyclic
	// calls from crashing the program.
	visited.add(v)

	// fmt.Printf("! check SSA value %s: %[1]T\n", v)

	// This is the core of the algorithm.
	//
	// It handles traversing the SSA value and callgraph to identify
	// if any of the given sources were used to obtain the initial
	// SSA value (v). We handle this value, depending on its type,
	// where we "peel back" its references and relevant SSA
	// instructions to determine if any of the given sinks were
	// involved in the process.
	switch value := v.(type) {
	// We assume that constants, functions, and globals are safe.
	//
	// To be clear: functions and globals may not always safe.
	// Just generally speaking. So in order to support additional
	// analysis in the future these values may need to be considered.
	//
	// It is probably safe to consider constants are always safe.
	// But what if you wanted to check if a constant made it into
	// a sink?
	case *ssa.Const, *ssa.Function, *ssa.Global:
		return false, "", nil
	// Function parameters can obscure the analysis of the value,
	// because we need to step backwards through the callgraph path
	// (just one step?) to identify what actual value the caller used.
	case *ssa.Parameter:
		// Check if the parameter's type is a source.
		paramType := value.Type()
		if src, ok := matchSourceType(sources, paramType); ok {
			return true, src, value
		}

		// Check the parameter's referrers.
		refs := value.Referrers()
		if refs != nil {
			for _, ref := range *refs {
				refVal, isVal := ref.(ssa.Value)
				if isVal {
					tainted, src, tv := checkSSAValue(path, sources, refVal, visited)
					if tainted {
						return true, src, tv
					}
					continue
				}

				tainted, src, tv := checkSSAInstruction(path, sources, ref, visited)
				if tainted {
					return true, src, tv
				}
			}
		}

		for _, edge := range path {
			if edge == nil || edge.Callee == nil || edge.Callee.Func == nil || edge.Site == nil {
				continue
			}
			parent := value.Parent()
			if parent == nil {
				continue
			}
			if edge.Callee.Func != parent {
				continue
			}
			common := edge.Site.Common()
			if common == nil {
				continue
			}
			if idx := parameterCallArgIndex(parent, value); idx >= 0 && idx < len(common.Args) {
				arg := common.Args[idx]
				ta, src, tv := checkSSAValue(path, sources, arg, visited)
				if ta {
					return true, src, tv
				}
				if src, base := isExpressionDerivedFromSource(arg, sources); src != "" {
					return true, src, base
				}
				continue
			}
			if sig, ok := edge.Callee.Func.Type().(*types.Signature); ok {
				if params := sig.Params(); params != nil {
					for pi := 0; pi < params.Len(); pi++ {
						if params.At(pi).Name() != value.Name() {
							continue
						}
						argIndex := pi
						if sig.Recv() != nil {
							argIndex++
						}
						if argIndex < len(common.Args) {
							arg := common.Args[argIndex]
							ta, src, tv := checkSSAValue(path, sources, arg, visited)
							if ta {
								return true, src, tv
							}
							// Also check if the argument expression derives from a source via operand chains.
							if src, base := isExpressionDerivedFromSource(arg, sources); src != "" {
								return true, src, base
							}
						}
						break
					}
				}
			}
		}
	// Function calls can be a little tricky. We need to check a few things.
	// 1. See if the call itself was a source.
	// 2. See if any of the arguments was a source.
	// 3. See if the call value calls a source (anonymous functions).
	case *ssa.Call:
		// 1. Handle the case where we finally called a source.
		if src, ok := matchSourceCall(sources, &value.Call); ok {
			return true, src, value.Call.Value
		}

		// General receiver propagation: if the call has a receiver (method call) and
		// the receiver base object (recursively) derives from a source, mark call result tainted.
		if value.Call.Signature() != nil && value.Call.Signature().Recv() != nil && len(value.Call.Args) > 0 {
			recv := value.Call.Args[0]
			if src, ok := matchSourceType(sources, recv.Type()); ok {
				return true, src, recv
			}
			if tainted, src, tv := checkSSAValue(path, sources, recv, visited); tainted {
				return true, src, tv
			}
			if src, base := derivedFromSource(recv, sources); src != "" {
				return true, src, base
			}
			// Also check if receiver operand expression derives from source.
			if src, base := isExpressionDerivedFromSource(recv, sources); src != "" {
				return true, src, base
			}
		}

		if _, args, ok := defaultPropagatorForCall(&value.Call); ok {
			for _, arg := range args {
				tainted, src, tv := checkSSAValue(path, sources, arg, visited)
				if tainted {
					return true, src, tv
				}
			}
		}

		// 2. For local/static calls, taint the result only when a returned
		// value is tainted after mapping callee parameters back to call args.
		if tainted, src, tv := checkCallReturnValues(path, sources, value, -1, visited); tainted {
			return true, src, tv
		}

		// 3. Handle the case of a *ssa.Call from an anonymous function (*ssa.MakeClosure).
		tainted, src, tv := checkSSAValue(path, sources, value.Call.Value, visited)
		if tainted {
			return true, src, tv
		}
		// Memory allocations or addressing can be traversed using the value's
		// referrers. Each referrer is either an SSA value or instruction.
	case *ssa.Alloc:
		refs := value.Referrers()
		if refs != nil {
			for _, ref := range *refs {
				refVal, isVal := ref.(ssa.Value)
				if isVal {
					tainted, src, tv := checkSSAValue(path, sources, refVal, visited)
					if tainted {
						return true, src, tv
					}
					continue
				}

				tainted, src, tv := checkSSAInstruction(path, sources, ref, visited)
				if tainted {
					return true, src, tv
				}
			}
		}
		// Free variables can be traversed using the value's referrers, or the
		// value's parent's referrers. Each referrer is either an SSA value or
		// instruction.
		//
		// These can be tricky because they can be used in a few different ways,
		// preventing us from just checking the value's referrers in all cases.
	case *ssa.FreeVar:
		// First, walk direct referrers of the free variable.
		if refs := value.Referrers(); refs != nil {
			for _, ref := range *refs {
				if rv, ok := ref.(ssa.Value); ok {
					tainted, src, tv := checkSSAValue(path, sources, rv, visited)
					if tainted {
						return true, src, tv
					}
					continue
				}
				tainted, src, tv := checkSSAInstruction(path, sources, ref, visited)
				if tainted {
					return true, src, tv
				}
			}
		}

		// Then, try to find the allocation in the parent function that backs this free var
		// (pattern seen in closures capturing variables).
		if parent := value.Parent(); parent != nil {
			if parentFn := parent.Parent(); parentFn != nil {
				for _, block := range parentFn.DomPreorder() {
					for _, instr := range block.Instrs {
						v2, ok := instr.(ssa.Value)
						if !ok {
							continue
						}
						if alloc, ok := v2.(*ssa.Alloc); ok {
							if alloc.Comment == value.Name() {
								tainted, src, tv := checkSSAValue(path, sources, v2, visited)
								if tainted {
									return true, src, tv
								}
							}
							continue
						}
						// Fallback: analyze the value as an expression root to see if it derives from a source.
						tainted, src, tv := checkSSAValue(path, sources, v2, valueSet{})
						if tainted {
							return true, src, tv
						}
					}
				}
			}
		}
	case *ssa.IndexAddr:
		refs := value.Referrers()
		if refs != nil {
			for _, ref := range *refs {
				refVal, isVal := ref.(ssa.Value)
				if isVal {
					tainted, src, tv := checkSSAValue(path, sources, refVal, visited)
					if tainted {
						return true, src, tv
					}
					continue
				}

				tainted, src, tv := checkSSAInstruction(path, sources, ref, visited)
				if tainted {
					return true, src, tv
				}
			}
		}
		tainted, src, tv := checkSSAValue(path, sources, value.X, visited)
		if tainted {
			return true, src, tv
		}
	case *ssa.FieldAddr:
		/*
			value.String()
			=> "&r.URL [#1]"
			value.Type().String()
			=> "**net/url.URL"
			value.X.Type().String()
			=? "*net/http.Request"
		*/
		// If the base of the field address is a source (directly or via proto message),
		// then any field access derived from it is also tainted.
		if src, ok := matchSourceType(sources, value.X.Type()); ok {
			return true, src, value
		}
		// Also check if the base expression derives from a source via operand chains.
		if src, base := isExpressionDerivedFromSource(value.X, sources); src != "" {
			return true, src, base
		}

		tainted, src, tv := checkSSAValue(path, sources, value.X, visited)
		if tainted {
			return true, src, tv
		}

		refs := value.Referrers()
		if refs != nil {
			for _, ref := range *refs {
				refVal, isVal := ref.(ssa.Value)
				if isVal {
					tainted, src, tv := checkSSAValue(path, sources, refVal, visited)
					if tainted {
						return true, src, tv
					}
					continue
				}

				tainted, src, tv := checkSSAInstruction(path, sources, ref, visited)
				if tainted {
					return true, src, tv
				}
			}
		}
		indexableValueRefs := value.X.Referrers()
		if indexableValueRefs != nil {
			for _, ref := range *indexableValueRefs {
				refVal, isVal := ref.(ssa.Value)
				if isVal {
					tainted, src, tv := checkSSAValue(path, sources, refVal, visited)
					if tainted {
						return true, src, tv
					}
					continue
				}

				tainted, src, tv := checkSSAInstruction(path, sources, ref, visited)
				if tainted {
					return true, src, tv
				}
			}
		}
	case *ssa.MakeClosure:
		tainted, src, tv := checkSSAValue(path, sources, value.Fn, visited)
		if tainted {
			return true, src, tv
		}
		for _, binding := range value.Bindings {
			tainted, src, tv := checkSSAValue(path, sources, binding, visited)
			if tainted {
				return true, src, tv
			}
		}
	case *ssa.BinOp:
		// Check the left hand side operands of the binary operations.
		tainted, src, tv := checkSSAValue(path, sources, value.X, visited) // left
		if tainted {
			return true, src, tv
		}
		tainted, src, tv = checkSSAValue(path, sources, value.Y, visited) // right
		if tainted {
			return true, src, tv
		}
	case *ssa.UnOp:
		// Check the single operand.
		tainted, src, tv := checkSSAValue(path, sources, value.X, visited)
		if tainted {
			return true, src, tv
		}
	case *ssa.Slice:
		// Check the sliced value.
		tainted, src, tv := checkSSAValue(path, sources, value.X, visited)
		if tainted {
			return true, src, tv
		}
	case *ssa.MakeInterface:
		// Check the value being made into an interface.
		tainted, src, tv := checkSSAValue(path, sources, value.X, visited)
		if tainted {
			return true, src, tv
		}
	case *ssa.ChangeInterface:
		// Check the value being changed into an interface.
		tainted, src, tv := checkSSAValue(path, sources, value.X, visited)
		if tainted {
			return true, src, tv
		}

		// Check the value's referrers.
		refs := value.X.Referrers()
		for _, ref := range *refs {
			refVal, isVal := ref.(ssa.Value)
			if isVal {
				tainted, src, tv := checkSSAValue(path, sources, refVal, visited)
				if tainted {
					return true, src, tv
				}
				continue
			}

			tainted, src, tv := checkSSAInstruction(path, sources, ref, visited)
			if tainted {
				return true, src, tv
			}
		}
	case *ssa.TypeAssert:
		// Check the value being type asserted.
		tainted, src, tv := checkSSAValue(path, sources, value.X, visited)
		if tainted {
			return true, src, tv
		}
	case *ssa.Convert:
		// Check the value being converted.
		tainted, src, tv := checkSSAValue(path, sources, value.X, visited)
		if tainted {
			return true, src, tv
		}
	case *ssa.Extract:
		if call, ok := value.Tuple.(*ssa.Call); ok {
			tainted, src, tv := checkCallReturnValues(path, sources, call, value.Index, visited)
			if tainted {
				return true, src, tv
			}
		}
		// Check the value being extracted.
		tainted, src, tv := checkSSAValue(path, sources, value.Tuple, visited)
		if tainted {
			return true, src, tv
		}
	case *ssa.Lookup:
		// Check the string or map value being looked up.
		tainted, src, tv := checkSSAValue(path, sources, value.X, visited)
		if tainted {
			return true, src, tv
		}

		// Check the index value being looked up.
		refs := value.Index.Referrers()
		if refs != nil {
			for _, ref := range *refs {
				refVal, isVal := ref.(ssa.Value)
				if isVal {
					tainted, src, tv := checkSSAValue(path, sources, refVal, visited)
					if tainted {
						return true, src, tv
					}
					continue
				}

				tainted, src, tv := checkSSAInstruction(path, sources, ref, visited)
				if tainted {
					return true, src, tv
				}
			}
		}
	case *ssa.MakeMap:
		refs := value.Referrers()
		if refs != nil {
			for _, ref := range *refs {
				refVal, isVal := ref.(ssa.Value)
				if isVal {
					tainted, src, tv := checkSSAValue(path, sources, refVal, visited)
					if tainted {
						return true, src, tv
					}
					continue
				}

				tainted, src, tv := checkSSAInstruction(path, sources, ref, visited)
				if tainted {
					return true, src, tv
				}
			}
		}
	default:
		// fmt.Printf("? check SSA value %s: %[1]T\n", v)
		return false, "", nil
	}
	return false, "", nil
}

// checkSSAInstruction is used internally by checkSSAValue when it needs to traverse
// SSA instructions, like the contents of a calling function.
func checkSSAInstruction(path callgraphutil.Path, sources Sources, i ssa.Instruction, visited valueSet) (bool, string, ssa.Value) {
	// fmt.Printf("! check SSA instr %s: %[1]T\n", i)

	switch instr := i.(type) {
	case *ssa.Store:
		// Store instructions need to be checked for both the value being stored,
		// and the address being stored to.
		tainted, src, tv := checkSSAValue(path, sources, instr.Val, visited)
		if tainted {
			return true, src, tv
		}
		tainted, src, tv = checkSSAValue(path, sources, instr.Addr, visited)
		if tainted {
			return true, src, tv
		}
	case *ssa.Call:
		// Check the operands of the call instruction.
		for _, instrValue := range instr.Operands(nil) {
			if instrValue == nil {
				continue
			}
			iv := *instrValue
			tainted, src, tv := checkSSAValue(path, sources, iv, visited)
			if tainted {
				return true, src, tv
			}
		}
	case *ssa.MapUpdate:
		// Map update instructions need to be checked for both the map being updated,
		// and the key and value being updated.
		tainted, src, tv := checkSSAValue(path, sources, instr.Key, visited)
		if tainted {
			return true, src, tv
		}

		tainted, src, tv = checkSSAValue(path, sources, instr.Value, visited)
		if tainted {
			return true, src, tv
		}
	default:
		// fmt.Printf("? check SSA instr %s: %[1]T\n", i)
		return false, "", nil
	}
	return false, "", nil
}

func parameterCallArgIndex(fn *ssa.Function, param *ssa.Parameter) int {
	if fn == nil || param == nil {
		return -1
	}
	for i, p := range fn.Params {
		if p == param {
			return i
		}
	}
	return -1
}

func callString(cc *ssa.CallCommon) string {
	if cc == nil {
		return ""
	}
	if fn := cc.StaticCallee(); fn != nil {
		return fn.String()
	}
	if cc.Value != nil {
		return cc.Value.String()
	}
	return ""
}

func staticCallee(cc *ssa.CallCommon) *ssa.Function {
	if cc == nil {
		return nil
	}
	if fn := cc.StaticCallee(); fn != nil {
		return fn
	}
	switch v := cc.Value.(type) {
	case *ssa.Function:
		return v
	case *ssa.MakeClosure:
		if fn, ok := v.Fn.(*ssa.Function); ok {
			return fn
		}
	}
	return nil
}

func checkCallReturnValues(path callgraphutil.Path, sources Sources, call *ssa.Call, resultIndex int, visited valueSet) (bool, string, ssa.Value) {
	if call == nil {
		return false, "", nil
	}
	callee := staticCallee(&call.Call)
	if callee == nil || len(callee.Blocks) == 0 {
		return false, "", nil
	}
	if summaryDepth(path) >= defaultMaxSummaryDepth {
		return false, "", nil
	}

	summaryPath := make(callgraphutil.Path, 0, len(path)+1)
	summaryPath = append(summaryPath, path...)
	summaryPath = append(summaryPath, &callgraph.Edge{
		Site:   call,
		Callee: &callgraph.Node{Func: callee},
	})

	for _, block := range callee.Blocks {
		for _, instr := range block.Instrs {
			ret, ok := instr.(*ssa.Return)
			if !ok {
				continue
			}
			if resultIndex >= 0 {
				if resultIndex >= len(ret.Results) {
					continue
				}
				if tainted, src, tv := checkSSAValue(summaryPath, sources, ret.Results[resultIndex], visited); tainted {
					return true, src, tv
				}
				continue
			}
			for _, result := range ret.Results {
				if tainted, src, tv := checkSSAValue(summaryPath, sources, result, visited); tainted {
					return true, src, tv
				}
			}
		}
	}
	return false, "", nil
}

func summaryDepth(path callgraphutil.Path) int {
	depth := 0
	for _, edge := range path {
		if edge != nil && edge.Caller == nil && edge.Site != nil {
			depth++
		}
	}
	return depth
}

// hasProtoMessageMethod reports if the given type implements either the legacy
// ProtoMessage method or the modern ProtoReflect method used by protobuf
// message types commonly passed through gRPC services.
func hasProtoMessageMethod(t types.Type) bool {
	for _, candidate := range receiverTypeCandidatesForTaint(t) {
		methodSet := types.NewMethodSet(candidate)
		for i := 0; i < methodSet.Len(); i++ {
			sel := methodSet.At(i)
			if sel == nil {
				continue
			}
			m := sel.Obj()
			sig, ok := m.Type().(*types.Signature)
			if !ok || sig.Params().Len() != 0 {
				continue
			}
			switch m.Name() {
			case "ProtoMessage":
				if sig.Results().Len() == 0 {
					return true
				}
			case "ProtoReflect":
				if sig.Results().Len() == 1 {
					return true
				}
			}
		}
	}
	return false
}

func receiverTypeCandidatesForTaint(t types.Type) []types.Type {
	if t == nil {
		return nil
	}
	candidates := []types.Type{t}
	if ptr, ok := t.(*types.Pointer); ok {
		candidates = append(candidates, ptr.Elem())
	} else {
		candidates = append(candidates, types.NewPointer(t))
	}
	var out []types.Type
	for _, candidate := range candidates {
		if candidate == nil {
			continue
		}
		seen := false
		for _, existing := range out {
			if types.Identical(existing, candidate) {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, candidate)
		}
	}
	return out
}

// derivedFromSource attempts to walk backwards from v following common address/field/index chains
// to find a base value whose static type matches a declared source. Returns the source string and
// the base value if found.
func derivedFromSource(v ssa.Value, sources Sources) (string, ssa.Value) {
	seen := map[ssa.Value]struct{}{}
	var work []ssa.Value
	work = append(work, v)
	for len(work) > 0 {
		cur := work[len(work)-1]
		work = work[:len(work)-1]
		if _, ok := seen[cur]; ok {
			continue
		}
		seen[cur] = struct{}{}
		if src, ok := matchSourceValue(sources, cur); ok {
			return src, cur
		}
		switch c := cur.(type) {
		case *ssa.FieldAddr:
			work = append(work, c.X)
		case *ssa.IndexAddr:
			work = append(work, c.X)
		case *ssa.Slice:
			work = append(work, c.X)
		case *ssa.UnOp:
			work = append(work, c.X)
		case *ssa.MakeInterface:
			work = append(work, c.X)
		case *ssa.TypeAssert:
			work = append(work, c.X)
		case *ssa.Convert:
			work = append(work, c.X)
		case *ssa.Extract:
			work = append(work, c.Tuple)
		}
		// Also inspect referrers to chase allocations storing the base.
		if refs := cur.Referrers(); refs != nil {
			for _, r := range *refs {
				if rv, ok := r.(ssa.Value); ok {
					if _, done := seen[rv]; !done {
						work = append(work, rv)
					}
				}
			}
		}
	}
	return "", nil
}

// isExpressionDerivedFromSource performs a comprehensive traversal of the operand graph
// starting from the given SSA value to determine if any sub-expression ultimately derives
// from a source type. Unlike derivedFromSource which follows referrer chains outward,
// this function follows operand chains inward.
func isExpressionDerivedFromSource(v ssa.Value, sources Sources) (string, ssa.Value) {
	seen := map[ssa.Value]struct{}{}
	var work []ssa.Value
	work = append(work, v)

	for len(work) > 0 {
		cur := work[len(work)-1]
		work = work[:len(work)-1]

		if _, ok := seen[cur]; ok {
			continue
		}
		seen[cur] = struct{}{}

		// Check if this value's type is a source.
		if src, ok := matchSourceValue(sources, cur); ok {
			return src, cur
		}

		// Traverse operands based on SSA value type.
		switch c := cur.(type) {
		case *ssa.Call:
			for _, arg := range c.Call.Args {
				work = append(work, arg)
			}
			work = append(work, c.Call.Value)
		case *ssa.FieldAddr:
			work = append(work, c.X)
		case *ssa.IndexAddr:
			work = append(work, c.X)
			work = append(work, c.Index)
		case *ssa.Slice:
			work = append(work, c.X)
			if c.Low != nil {
				work = append(work, c.Low)
			}
			if c.High != nil {
				work = append(work, c.High)
			}
		case *ssa.BinOp:
			work = append(work, c.X, c.Y)
		case *ssa.UnOp:
			work = append(work, c.X)
		case *ssa.MakeInterface:
			work = append(work, c.X)
		case *ssa.TypeAssert:
			work = append(work, c.X)
		case *ssa.Convert:
			work = append(work, c.X)
		case *ssa.Extract:
			work = append(work, c.Tuple)
		case *ssa.Lookup:
			work = append(work, c.X)
			work = append(work, c.Index)
		}
	}

	return "", nil
}
