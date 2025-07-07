package taint

import (
	"go/types"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	"github.com/picatz/taint/callgraphutil"
)

// Result is an individual finding from a taint check.
//
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
	// The results of the taint check.
	results := Results{}

	// For each sink given, identify the individual paths from
	// within the callgraph that those sinks can end up as
	// the final node path (the "sink path").
	for sink := range sinks {
		sinkPaths := callgraphutil.PathsSearchCallTo(cg.Root, sink)

		// fmt.Println("sink paths:", len(sinkPaths))

		for _, sinkPath := range sinkPaths {
			// fmt.Println("sink path:", sinkPath)
			// Ensure the path isn't empty (which can happen?!).
			//
			// TODO: ensure returned paths from within searched paths
			//       are never empty. That's just silly.
			if sinkPath.Empty() {
				continue
			}

			// Check if the last edge (e.g. a SQL query) used any of the given
			// sources (e.g. user input in an HTTP request) to identify if it
			// was "tainted".
			tainted, src, tv := checkPath(sinkPath, sources)
			if tainted {
				// Extract the last edge from the last part of the path
				// to include the calle as the sink in the result.
				lastEdge := sinkPath.Last()

				// Add the result to the list of results.
				results = append(results, Result{
					Path:        sinkPath,
					SourceType:  src,
					SourceValue: tv,
					SinkType:    lastEdge.Callee.String(),
					SinkValue:   lastEdge.Site.Value(),
				})
			}
		}
	}

	// Return the results of the taint check.
	return results
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
		if src, ok := sources.includes("google.golang.org/protobuf/proto.Message"); ok {
			if hasProtoMessageMethod(paramType) {
				return true, src, value
			}
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

		// TODO: consider if we can remove the range with a single
		//       step backwards?
		for _, edge := range path {
			// Find the caller that used the function parameter's parent (the function).
			if edge.Callee.Func == v.Parent() {
				// Inspect the instructions of the caller's function to identify
				// the relevant call using the function parameter.
				for _, block := range edge.Caller.Func.DomPreorder() {
					for _, instr := range block.Instrs {
						callInstr, ok := instr.(*ssa.Call)
						if !ok {
							continue
						}
						if callInstr.Call.Value.Pos() == edge.Callee.Func.Pos() {
							tainted, src, tv := checkSSAInstruction(path, sources, instr, visited)
							if tainted {
								return true, src, tv
							}
						}
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
		callTypeStr := value.Call.Value.String()
		if src, ok := sources.includes(callTypeStr); ok {
			return true, src, value.Call.Value
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
	// Free variables can be traversed using the value's referrers, or the
	// value's parent's referrers. Each referrer is either an SSA value or
	// instruction.
	//
	// These can be tricky because they can be used in a few different ways,
	// preventing us from just checking the value's referrers in all cases.
	case *ssa.FreeVar:
		refs := value.Referrers()
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

		// Handle the case of an anonymous function being injected into the child scope.
		//
		//  Example
		//
		//   ╭──────────────────────────────╮
		//   ↓                              │
		//  user := r.URL.Query()["query"]  │      Parent scope
		//  func() {                        │      ┄┄┄┄┄┄┄┄┄┄┄┄
		//    userValue := user[0] ←────────╯      Child scope
		//    business(db, func() *string {
		//      return &userValue
		//    }())
		//  }()
		//
		// TODO: consider checking parentFn params and other places?
		parentFn := value.Parent().Parent()
		for _, block := range parentFn.DomPreorder() {
			for _, instr := range block.Instrs {
				// fmt.Printf("\t - check SSA value %s: %[1]T ~ %[2]v\n", instr, value.Name())
				val, isval := instr.(ssa.Value)
				if !isval {
					continue
				}
				alloc, isalloc := val.(*ssa.Alloc)
				if isalloc {
					if alloc.Comment == value.Name() {
						tainted, src, tv := checkSSAValue(path, sources, val, visited)
						if tainted {
							return true, src, tv
						}
					}
					continue
				}

				// TODO: handle more cases like this...
				//
				//  Example
				//
				//  mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				//  	var input map[string]any ←────────╮         ↑
				//                      ╭─────────────────↓─────────╯
				// 		json.NewDecoder(r.Body).Decode(&input) ←────╮
				//	                                               	│
				// 		func() {									↓
				// 			userValue := fmt.Sprintf("%s", input["query"]) ←────────╮
				// 			business(db, func() *string {							│
				// 				return &userValue ←─────────────────────────────────╯
				// 			}())
				// 		}()
				//  })
				//
				tainted, src, tv := checkSSAValue(path, sources, val, valueSet{})
				if tainted {
					return true, src, tv
				}
			}
		}
	case *ssa.IndexAddr:
		refs := value.Referrers()
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
		if src, ok := sources.includes(value.X.Type().String()); ok {
			return true, src, value
		}
		if src, ok := sources.includes("google.golang.org/protobuf/proto.Message"); ok {
			if hasProtoMessageMethod(value.X.Type()) {
				return true, src, value
			}
		}

		tainted, src, tv := checkSSAValue(path, sources, value.X, visited)
		if tainted {
			return true, src, tv
		}

		refs := value.Referrers()
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
		indexableValueRefs := value.X.Referrers()
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
