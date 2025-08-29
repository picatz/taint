package taint

import (
	"fmt"
	"go/types"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	"github.com/picatz/taint/callgraphutil"
)

// findAllCallSitePaths finds all paths that end with a call to the specified sink function.
// Unlike PathsSearchCallTo which finds paths to the function node, this finds paths to
// individual call sites (edges) that call the function.
func findAllCallSitePaths(cg *callgraph.Graph, sinkFunc string) callgraphutil.Paths {
	var paths callgraphutil.Paths

	// Find all nodes that have outgoing edges calling the sink function
	for _, node := range cg.Nodes {
		for _, edge := range node.Out {
			match := false
			if edge.Callee != nil && edge.Callee.Func != nil && edge.Callee.Func.String() == sinkFunc {
				match = true
			} else if edge.Site != nil {
				cc := edge.Site.Common()
				if cc != nil {
					// Match direct function calls (e.g., log.Println)
					if cc.Value != nil && !cc.IsInvoke() {
						switch v := cc.Value.(type) {
						case *ssa.Function:
							if v.String() == sinkFunc {
								match = true
							} else if sig := v.Signature; sig != nil && sig.Recv() != nil {
								recvStr := types.TypeString(sig.Recv().Type(), nil)
								methodSig := fmt.Sprintf("(%s).%s", recvStr, v.Name())
								if methodSig == sinkFunc {
									match = true
								}
							}
						case *ssa.MakeClosure:
							if fn, ok := v.Fn.(*ssa.Function); ok {
								if fn.String() == sinkFunc {
									match = true
								} else if sig := fn.Signature; sig != nil && sig.Recv() != nil {
									recvStr := types.TypeString(sig.Recv().Type(), nil)
									methodSig := fmt.Sprintf("(%s).%s", recvStr, fn.Name())
									if methodSig == sinkFunc {
										match = true
									}
								}
							}
						}
					}
					// Match static callee if resolved by SSA (covers wrappers)
					if !match {
						if fn := cc.StaticCallee(); fn != nil {
							if fn.String() == sinkFunc {
								match = true
							} else if sig := fn.Signature; sig != nil && sig.Recv() != nil {
								recvStr := types.TypeString(sig.Recv().Type(), nil)
								methodSig := fmt.Sprintf("(%s).%s", recvStr, fn.Name())
								if methodSig == sinkFunc {
									match = true
								}
							}
						}
					}
					// Match method invokes via receiver type (e.g., (*log.Logger).Println)
					if !match && cc.IsInvoke() && cc.Method != nil && cc.Signature() != nil && cc.Signature().Recv() != nil {
						recv := cc.Signature().Recv().Type()
						// Build signature string like "(*pkg.Type).Method"
						recvStr := types.TypeString(recv, nil)
						methodSig := fmt.Sprintf("(%s).%s", recvStr, cc.Method.Name())
						if methodSig == sinkFunc {
							match = true
						} else {
							// try non-pointer Alt
							alt := strings.TrimPrefix(recvStr, "*")
							altSig := fmt.Sprintf("(%s).%s", alt, cc.Method.Name())
							if altSig == sinkFunc {
								match = true
							}
						}
					}
					// Static callee fallback (covers bound methods/wrappers)
					if !match {
						if fn := cc.StaticCallee(); fn != nil {
							if fn.String() == sinkFunc {
								match = true
							} else if sig := fn.Signature; sig != nil && sig.Recv() != nil {
								recvStr := types.TypeString(sig.Recv().Type(), nil)
								methodSig := fmt.Sprintf("(%s).%s", recvStr, fn.Name())
								if methodSig == sinkFunc {
									match = true
								} else {
									alt := strings.TrimPrefix(recvStr, "*")
									altSig := fmt.Sprintf("(%s).%s", alt, fn.Name())
									if altSig == sinkFunc {
										match = true
									}
								}
							}
						}
					}
				}
			}
			if match {
				// Found a call edge to the sink function.
				// First choice: build immediate caller → node → sink paths to capture direct user callsites.
				// builtAnyImmediate := false
				for _, pc := range cg.Nodes {
					for _, e2 := range pc.Out {
						if e2 != nil && e2.Callee == node {
							paths = append(paths, callgraphutil.Path{e2, edge})
							// builtAnyImmediate = true
						}
					}
				}
				// Also include any full paths from root → ... → node, then append the sink edge.
				if cg != nil && cg.Root != nil {
					if rootPaths := callgraphutil.PathsSearchCallTo(cg.Root, node.Func.String()); len(rootPaths) > 0 {
						for _, rp := range rootPaths {
							paths = append(paths, append(rp, edge))
						}
					}
				}

				// Second choice: build reverse paths by climbing immediate callers up to a small depth,
				// then append the sink edge. This helps when graphs are disconnected from root.
				type frame struct {
					n    *callgraph.Node
					path callgraphutil.Path
					d    int
				}
				const maxBackDepth = 4
				q := []frame{{n: node, path: nil, d: 0}}
				builtAny := false
				for len(q) > 0 {
					cur := q[0]
					q = q[1:]
					if cur.d >= maxBackDepth {
						continue
					}
					// find direct callers of cur.n
					for _, pc := range cg.Nodes {
						for _, e2 := range pc.Out {
							if e2 != nil && e2.Callee == cur.n {
								// Build a new path with e2 prepended to the existing path
								newPath := append(callgraphutil.Path{e2}, cur.path...)
								q = append(q, frame{n: pc, path: newPath, d: cur.d + 1})
								// Append the sink edge to form callers → ... → node → sink
								final := append(append(callgraphutil.Path{}, newPath...), edge)
								paths = append(paths, final)
								builtAny = true
							}
						}
					}
				}
				if builtAny {
					continue
				}

				// Last resort: include the single sink call edge so the callsite is at least evaluated.
				paths = append(paths, callgraphutil.Path{edge})
			}
		}
	}

	return paths
} // Result is an individual finding from a taint check.
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
	// Select the shortest path per (sink callsite position, source type)
	bestByKey := make(map[string]Result)

	// For each sink given, identify the individual paths from
	// within the callgraph that those sinks can end up as
	// the final node path (the "sink path").
	for sink := range sinks {
		// Find all call edges that call the sink function
		sinkPaths := findAllCallSitePaths(cg, sink)

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
			tainted, src, tv := checkPath(sinkPath, sources)

			if tainted {
				lastEdge := sinkPath.Last()
				if lastEdge == nil || lastEdge.Site == nil || lastEdge.Callee == nil {
					continue
				}
				sinkPos := lastEdge.Site.Pos()
				key := fmt.Sprintf("%d|%s", sinkPos, src)
				candidate := Result{
					Path:        sinkPath,
					SourceType:  src,
					SourceValue: tv,
					SinkType:    lastEdge.Callee.Func.String(),
					SinkValue:   lastEdge.Site.Value(),
				}
				// Prefer richer (longer) paths so parameter mapping across wrappers is preserved
				if prev, ok := bestByKey[key]; !ok || len(candidate.Path) > len(prev.Path) {
					bestByKey[key] = candidate
				}
			}
		}
	}

	// Emit results in arbitrary order
	out := make(Results, 0, len(bestByKey))
	for _, r := range bestByKey {
		out = append(out, r)
	}
	return out
}

// checkPath implements taint analysis that can be used to identify if the given
// callgraph path contains information from taintable sources (typically user input).
func checkPath(path callgraphutil.Path, sources Sources) (bool, string, ssa.Value) {
	// Ensure the path isn't empty (which can happen?!).
	if path.Empty() {
		return false, "", nil
	}

	// Value set used to keep track of values which were already visited
	// during the taint analysis. This prevents cyclic calls from crashing
	// the program.
	visited := valueSet{}

	// Start at last call from the path to see if any of the given sources were used
	// along with it to perform an action (e.g. SQL query).
	tainted, src, tv := checkSSAValue(path, sources, path.Last().Site.Value(), visited)
	if tainted {
		return true, src, tv
	}

	return false, "", nil
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
		paramTypeStr := paramType.String()
		if src, ok := sources.includes(paramTypeStr); ok {
			return true, src, value
		}

		// Check if the parameter type implements proto.Message when the
		// caller provided it as a potential source.
		if ok, src := protoMessageSource(sources, paramType); ok {
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
			if value.Parent() == nil {
				continue
			}
			if edge.Callee.Func != value.Parent() {
				continue
			}
			if sig, ok := edge.Callee.Func.Type().(*types.Signature); ok {
				if params := sig.Params(); params != nil {
					for pi := 0; pi < params.Len(); pi++ {
						if params.At(pi).Name() != value.Name() {
							continue
						}
						common := edge.Site.Common()
						if common != nil && pi < len(common.Args) {
							arg := common.Args[pi]
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
		callTypeStr := ""
		if value.Call.Value != nil {
			callTypeStr = value.Call.Value.String()
		}
		if src, ok := sources.includes(callTypeStr); ok {
			return true, src, value.Call.Value
		}

		// General receiver propagation: if the call has a receiver (method call) and
		// the receiver base object (recursively) derives from a source, mark call result tainted.
		if value.Call.Signature() != nil && value.Call.Signature().Recv() != nil && len(value.Call.Args) > 0 {
			recv := value.Call.Args[0]
			if src, ok := sources.includes(recv.Type().String()); ok {
				return true, src, recv
			}
			if ok, src := protoMessageSource(sources, recv.Type()); ok {
				return true, src, recv
			}
			if src, base := derivedFromSource(recv, sources); src != "" {
				return true, src, base
			}
			// Also check if receiver operand expression derives from source.
			if src, base := isExpressionDerivedFromSource(recv, sources); src != "" {
				return true, src, base
			}
		}

		// Special propagation: fmt.Sprintf inherits taint if any non-format argument is tainted.
		if callTypeStr == "fmt.Sprintf" {
			for i, arg := range value.Call.Args {
				// First argument usually the format string constant; still check all to be safe.
				_ = i
				tainted, src, tv := checkSSAValue(path, sources, arg, visited)
				if tainted {
					return true, src, tv
				}
			}
		}

		// Special propagation: io.ReadAll – if the reader argument is tainted, result is tainted.
		if callTypeStr == "io.ReadAll" {
			for _, arg := range value.Call.Args {
				tainted, src, tv := checkSSAValue(path, sources, arg, visited)
				if tainted {
					return true, src, tv
				}
			}
		}
		// 2. Handle the arguments of the call.
		for _, arg := range value.Call.Args {
			tainted, src, tv := checkSSAValue(path, sources, arg, visited)
			if tainted {
				return true, src, tv
			}
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
		if src, ok := sources.includes(value.X.Type().String()); ok {
			return true, src, value
		}
		if ok, src := protoMessageSource(sources, value.X.Type()); ok {
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

// protoMessageSource checks if the given type implements proto.Message when that
// type is present in the provided sources list. It returns true with the source
// string if so.
func protoMessageSource(sources Sources, t types.Type) (bool, string) {
	if src, ok := sources.includes("google.golang.org/protobuf/proto.Message"); ok {
		if hasProtoMessageMethod(t) {
			return true, src
		}
	}
	return false, ""
}

// hasProtoMessageMethod reports if the given type implements a ProtoMessage method
// with no parameters and no results, which is used to identify protobuf message
// types commonly used with gRPC services.
func hasProtoMessageMethod(t types.Type) bool {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}

	named, ok := t.(*types.Named)
	if !ok {
		return false
	}

	for i := 0; i < named.NumMethods(); i++ {
		m := named.Method(i)
		if m.Name() != "ProtoMessage" {
			continue
		}
		if sig, ok := m.Type().(*types.Signature); ok {
			if sig.Params().Len() == 0 && sig.Results().Len() == 0 {
				return true
			}
		}
	}
	return false
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
		if src, ok := sources.includes(cur.Type().String()); ok {
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
		if src, ok := sources.includes(cur.Type().String()); ok {
			return src, cur
		}

		// Check proto message sources.
		if ok, src := protoMessageSource(sources, cur.Type()); ok {
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
