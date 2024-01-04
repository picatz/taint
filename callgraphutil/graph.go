package callgraphutil

import (
	"bytes"
	"fmt"
	"go/types"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

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
func NewGraph(root *ssa.Function, srcFns ...*ssa.Function) (*callgraph.Graph, error) {
	g := &callgraph.Graph{
		Nodes: make(map[*ssa.Function]*callgraph.Node),
	}

	g.Root = g.CreateNode(root)

	allFns := ssautil.AllFunctions(root.Prog)

	for _, srcFn := range srcFns {
		// debug("adding src function %d/%d: %v\n", i+1, len(srcFns), srcFn)

		err := AddFunction(g, srcFn, allFns)
		if err != nil {
			return g, fmt.Errorf("failed to add src function %v: %w", srcFn, err)
		}

		for _, block := range srcFn.DomPreorder() {
			for _, instr := range block.Instrs {
				checkBlockInstruction(root, allFns, g, srcFn, instr)
			}
		}
	}

	return g, nil
}

// checkBlockInstruction checks the given instruction for any function calls, adding
// edges to the call graph as needed and recursively adding any new functions to the graph
// that are discovered during the process (typically via interface methods).
func checkBlockInstruction(root *ssa.Function, allFns map[*ssa.Function]bool, g *callgraph.Graph, fn *ssa.Function, instr ssa.Instruction) error {
	// debug("\tcheckBlockInstruction: %v\n", instr)
	switch instrt := instr.(type) {
	case *ssa.Call:
		var instrCall *ssa.Function

		switch callt := instrt.Call.Value.(type) {
		case *ssa.Function:
			instrCall = callt

			for _, instrtCallArg := range instrt.Call.Args {
				switch instrtCallArgt := instrtCallArg.(type) {
				case *ssa.ChangeInterface:
					// Track type casts through matching interface methods.
					//
					// # Example
					//
					//  func buffer(r io.Reader) io.Reader {
					//  	return bufio.NewReader(r)
					//  }
					//
					//  func mirror(w http.ResponseWriter, r *http.Request) {
					//  	_, err := io.Copy(w, buffer(r.Body)) // w is an http.ResponseWriter, convert to io.Writer for io.Copy
					//  	if err != nil {
					//  		panic(err)
					//  	}
					//  }
					//
					// io.Copy is called with an io.Writer, but the underlying type is a net/http.ResponseWriter.
					//
					//   n11:net/http.HandleFunc → n1:c.mirror → n5:io.Copy → n6:(io.Writer).Write → n7:(net/http.ResponseWriter).Write
					//
					switch argtt := instrtCallArgt.Type().Underlying().(type) {
					case *types.Interface:
						numMethods := argtt.NumMethods()

						for i := 0; i < numMethods; i++ {
							method := argtt.Method(i)

							methodPkg := method.Pkg()
							if methodPkg == nil {
								// Universe scope method, such as "error.Error".
								continue
							}

							pkg := root.Prog.ImportedPackage(method.Pkg().Path())
							if pkg == nil {
								// This is a method from a package that is not imported, so we skip it.
								continue
							}
							fn := pkg.Func(method.Name())
							if fn == nil {
								fn = pkg.Prog.NewFunction(method.Name(), method.Type().(*types.Signature), "callgraph")
							}

							callgraph.AddEdge(g.CreateNode(instrCall), instrt, g.CreateNode(fn))

							switch xType := instrtCallArgt.X.Type().(type) {
							case *types.Named:
								named := xType

								pkg2 := root.Prog.ImportedPackage(named.Obj().Pkg().Path())

								methodSet := pkg2.Prog.MethodSets.MethodSet(named)
								methodSel := methodSet.Lookup(pkg2.Pkg, method.Name())

								if methodSel == nil {
									continue
								}

								methodType := methodSel.Type().(*types.Signature)

								fn2 := pkg2.Func(method.Name())
								if fn2 == nil {
									fn2 = pkg2.Prog.NewFunction(method.Name(), methodType, "callgraph")
								}

								callgraph.AddEdge(g.CreateNode(fn), instrt, g.CreateNode(fn2))
							default:
								continue
							}
						}
					}
				}
			}
		case *ssa.MakeClosure:
			switch calltFn := callt.Fn.(type) {
			case *ssa.Function:
				instrCall = calltFn
			}
		case *ssa.Parameter:
			// This is likely a method call, so we need to
			// get the function from the method receiver which
			// is not available directly from the call instruction,
			// but rather from the package level function.

			// Skip this instruction if we could not determine
			// the function being called.
			if !instrt.Call.IsInvoke() || (instrt.Call.Method == nil) {
				return nil
			}

			// TODO: should we share the resulting function?
			instrtCallMethodPkg := instrt.Call.Method.Pkg()
			if instrtCallMethodPkg == nil {
				// This is an interface method call from the universe scope, such as "error.Error",
				// so we return nil to skip this instruction, which we will assume is safe.
				return nil
			} else {
				pkg := root.Prog.ImportedPackage(instrt.Call.Method.Pkg().Path())

				fn := pkg.Func(instrt.Call.Method.Name())
				if fn == nil {
					fn = pkg.Prog.NewFunction(instrt.Call.Method.Name(), instrt.Call.Signature(), "callgraph")
				}
				instrCall = fn
			}
		default:
			// case *ssa.TypeAssert: ??
			// fmt.Printf("unknown call type: %v: %[1]T\n", callt)
		}

		// If we could not determine the function being
		// called, skip this instruction.
		if instrCall == nil {
			return nil
		}

		callgraph.AddEdge(g.CreateNode(fn), instrt, g.CreateNode(instrCall))

		err := AddFunction(g, instrCall, allFns)
		if err != nil {
			return fmt.Errorf("failed to add function %v from block instr: %w", instrCall, err)
		}

		// attempt to link function arguments that are functions
		for a := 0; a < len(instrt.Call.Args); a++ {
			arg := instrt.Call.Args[a]
			switch argt := arg.(type) {
			case *ssa.Function:
				// TODO: check if edge already exists?
				callgraph.AddEdge(g.CreateNode(instrCall), instrt, g.CreateNode(argt))
			case *ssa.MakeClosure:
				switch argtFn := argt.Fn.(type) {
				case *ssa.Function:
					callgraph.AddEdge(g.CreateNode(instrCall), instrt, g.CreateNode(argtFn))
				}
			}
		}
	}

	// Delete duplicate edges that may have been added, which is a responsibility of the caller
	// when using the callgraph.AddEdge function directly.
	for _, n := range g.Nodes {
		// debug("checking node %v\n", n)
		for i := 0; i < len(n.Out); i++ {
			for j := i + 1; j < len(n.Out); j++ {
				if n.Out[i].Callee == n.Out[j].Callee {
					// debug("deleting duplicate edge %v\n", n.Out[j])
					n.Out = append(n.Out[:j], n.Out[j+1:]...)
					j--
				}
			}
		}
	}

	return nil
}

// AddFunction analyzes the given target SSA function, adding information to the call graph.
//
// Based on the implementation of golang.org/x/tools/cmd/guru/callers.go:
// https://cs.opensource.google/go/x/tools/+/master:cmd/guru/callers.go;drc=3e0d083b858b3fdb7d095b5a3deb184aa0a5d35e;bpv=1;bpt=1;l=90
func AddFunction(cg *callgraph.Graph, target *ssa.Function, allFns map[*ssa.Function]bool) error {
	// debug("\tAddFunction: %v (all funcs %d)\n", target, len(allFns))

	// First check if we have already processed this function.
	if _, ok := cg.Nodes[target]; ok {
		return nil
	}

	targetNode := cg.CreateNode(target)

	// Find receiver type (for methods).
	var recvType types.Type
	if recv := target.Signature.Recv(); recv != nil {
		recvType = recv.Type()
	}

	if len(allFns) == 0 {
		allFns = ssautil.AllFunctions(target.Prog)
	}

	// Find all direct calls to function,
	// or a place where its address is taken.
	for progFn := range allFns {
		var space [32]*ssa.Value // preallocate

		for _, block := range progFn.DomPreorder() {
			for _, instr := range block.Instrs {
				// Is this a method (T).f of a concrete type T
				// whose runtime type descriptor is address-taken?
				// (To be fully sound, we would have to check that
				// the type doesn't make it to reflection as a
				// subelement of some other address-taken type.)
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

				// Direct call to target?
				rands := instr.Operands(space[:0])
				if site, ok := instr.(ssa.CallInstruction); ok && site.Common().Value == target {
					callgraph.AddEdge(cg.CreateNode(progFn), site, targetNode)
					rands = rands[1:] // skip .Value (rands[0])
				}

				// Address-taken?
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
