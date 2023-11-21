package callgraph

import (
	"bytes"
	"fmt"
	"go/token"
	"go/types"
	"sync"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// A Graph represents a call graph.
//
// A graph may contain nodes that are not reachable from the root.
// If the call graph is sound, such nodes indicate unreachable
// functions.
type Graph struct {
	Root  *Node                   // the distinguished root node
	Nodes map[*ssa.Function]*Node // all nodes by function
}

// New returns a new Graph with the specified root node.
func New(root *ssa.Function, srcFns ...*ssa.Function) (*Graph, error) {
	g := &Graph{
		Nodes: make(map[*ssa.Function]*Node),
	}

	g.Root = g.CreateNode(root)

	allFns := ssautil.AllFunctions(root.Prog)

	for _, srcFn := range srcFns {
		err := g.AddFunction(srcFn, allFns)
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

func checkBlockInstruction(root *ssa.Function, allFns map[*ssa.Function]bool, g *Graph, fn *ssa.Function, instr ssa.Instruction) error {
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

							pkg := root.Prog.ImportedPackage(method.Pkg().Path())
							fn := pkg.Prog.NewFunction(method.Name(), method.Type().(*types.Signature), "callgraph")
							AddEdge(g.CreateNode(instrCall), instrt, g.CreateNode(fn))

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

								fn2 := pkg2.Prog.NewFunction(method.Name(), methodType, "callgraph")

								AddEdge(g.CreateNode(fn), instrt, g.CreateNode(fn2))
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
			pkg := root.Prog.ImportedPackage(instrt.Call.Method.Pkg().Path())
			fn := pkg.Prog.NewFunction(instrt.Call.Method.Name(), instrt.Call.Signature(), "callgraph")
			instrCall = fn
		default:
			// case *ssa.TypeAssert: ??
			// fmt.Printf("unknown call type: %v: %[1]T\n", callt)
		}

		// If we could not determine the function being
		// called, skip this instruction.
		if instrCall == nil {
			return nil
		}

		AddEdge(g.CreateNode(fn), instrt, g.CreateNode(instrCall))

		err := g.AddFunction(instrCall, allFns)
		if err != nil {
			return fmt.Errorf("failed to add function %v from block instr: %w", instrCall, err)
		}

		// attempt to link function arguments that are functions
		for a := 0; a < len(instrt.Call.Args); a++ {
			arg := instrt.Call.Args[a]
			switch argt := arg.(type) {
			case *ssa.Function:
				// TODO: check if edge already exists?
				AddEdge(g.CreateNode(instrCall), instrt, g.CreateNode(argt))
			case *ssa.MakeClosure:
				switch argtFn := argt.Fn.(type) {
				case *ssa.Function:
					AddEdge(g.CreateNode(instrCall), instrt, g.CreateNode(argtFn))
				}
			}
		}
	}
	return nil
}

// AddFunction analyzes the given target SSA function, adding information to the call graph.
// https://cs.opensource.google/go/x/tools/+/master:cmd/guru/callers.go;drc=3e0d083b858b3fdb7d095b5a3deb184aa0a5d35e;bpv=1;bpt=1;l=90
func (cg *Graph) AddFunction(target *ssa.Function, allFns map[*ssa.Function]bool) error {
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
					AddEdge(cg.CreateNode(progFn), site, targetNode)
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

// CreateNode returns the Node for fn, creating it if not present.
func (g *Graph) CreateNode(fn *ssa.Function) *Node {
	n, ok := g.Nodes[fn]
	if !ok {
		n = &Node{Func: fn, ID: len(g.Nodes)}
		g.Nodes[fn] = n
		return n
	}
	return n
}

func (g *Graph) String() string {
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

// A Node represents a node in a call graph.
type Node struct {
	sync.RWMutex
	Func *ssa.Function // the function this node represents
	ID   int           // 0-based sequence number
	In   []*Edge       // unordered set of incoming call edges (n.In[*].Callee == n)
	Out  []*Edge       // unordered set of outgoing call edges (n.Out[*].Caller == n)
}

func (n *Node) String() string {
	return fmt.Sprintf("n%d:%s", n.ID, n.Func)
}

// A Edge represents an edge in the call graph.
//
// Site is nil for edges originating in synthetic or intrinsic
// functions, e.g. reflect.Call or the root of the call graph.
type Edge struct {
	Caller *Node
	Site   ssa.CallInstruction
	Callee *Node
}

func (e Edge) String() string {
	return fmt.Sprintf("%s → %s", e.Caller, e.Callee)
}

func (e Edge) Description() string {
	var prefix string
	switch e.Site.(type) {
	case nil:
		return "synthetic call"
	case *ssa.Go:
		prefix = "concurrent "
	case *ssa.Defer:
		prefix = "deferred "
	}
	return prefix + e.Site.Common().Description()
}

func (e Edge) Pos() token.Pos {
	if e.Site == nil {
		return token.NoPos
	}
	return e.Site.Pos()
}

// AddEdge adds the edge (caller, site, callee) to the call graph.
func AddEdge(caller *Node, site ssa.CallInstruction, callee *Node) {
	e := &Edge{caller, site, callee}

	var existingCalleeEdge bool

	callee.RLock()
	for _, in := range callee.In {
		if in.String() == e.String() {
			existingCalleeEdge = true
			break
		}
	}
	callee.RUnlock()

	if !existingCalleeEdge {
		callee.Lock()
		callee.In = append(callee.In, e)
		callee.Unlock()
	}

	var existingCallerEdge bool

	caller.RLock()
	for _, out := range caller.Out {
		if out.String() == e.String() {
			existingCallerEdge = true
			break
		}
	}
	caller.RUnlock()

	if !existingCallerEdge {
		caller.Lock()
		caller.Out = append(caller.Out, e)
		caller.Unlock()
	}
}

// GraphVisitEdges visits all the edges in graph g in depth-first order.
// The edge function is called for each edge in postorder.  If it
// returns non-nil, visitation stops and GraphVisitEdges returns that
// value.
func (g *Graph) VisitEdges(edge func(*Edge) error) error {
	seen := make(map[*Node]bool)
	var visit func(n *Node) error
	visit = func(n *Node) error {
		if !seen[n] {
			seen[n] = true
			for _, e := range n.Out {
				if err := visit(e.Callee); err != nil {
					return err
				}
				if err := edge(e); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, n := range g.Nodes {
		if err := visit(n); err != nil {
			return err
		}
	}
	return nil
}

type Path []*Edge

func (p Path) Empty() bool {
	return len(p) == 0
}

func (p Path) First() *Edge {
	if len(p) == 0 {
		return nil
	}
	return p[0]
}

func (p Path) Last() *Edge {
	if len(p) == 0 {
		return nil
	}
	return p[len(p)-1]
}

// String returns a string representation of the path which
// is a sequence of edges separated by " → ".
//
// Intended to be used while debugging.
func (p Path) String() string {
	var buf bytes.Buffer
	for i, e := range p {
		if i == 0 {
			buf.WriteString(e.Caller.String())
		}

		buf.WriteString(" → ")

		buf.WriteString(e.Callee.String())
	}
	return buf.String()
}

type Paths []Path

func PathSearch(start *Node, isEnd func(*Node) bool) Path {
	stack := make(Path, 0, 32)
	seen := make(map[*Node]bool)
	var search func(n *Node) Path
	search = func(n *Node) Path {
		if !seen[n] {
			seen[n] = true
			if isEnd(n) {
				return stack
			}
			for _, e := range n.Out {
				stack = append(stack, e) // push
				if found := search(e.Callee); found != nil {
					return found
				}
				stack = stack[:len(stack)-1] // pop
			}
		}
		return nil
	}
	return search(start)
}

func PathsSearch(start *Node, isEnd func(*Node) bool) Paths {
	paths := Paths{}

	stack := make(Path, 0, 32)
	seen := make(map[*Node]bool)
	var search func(n *Node)
	search = func(n *Node) {
		if !seen[n] {
			seen[n] = true
			if isEnd(n) {
				paths = append(paths, stack)

				stack = make(Path, 0, 32)
				seen = make(map[*Node]bool)
				return
			}
			for _, e := range n.Out {
				if e.Caller.Func.Name() != "main" {
					stack = append(stack, e) // push
				}
				search(e.Callee)
				if len(stack) == 0 {
					continue
				}
				if e.Caller.Func.Name() != "main" {
					stack = stack[:len(stack)-1] // pop
				}
			}
		}
	}
	search(start)

	return paths
}

func CalleesOf(caller *Node) map[*Node]bool {
	callees := make(map[*Node]bool)
	for _, e := range caller.Out {
		callees[e.Callee] = true
	}
	return callees
}

func CallersOf(callee *Node) map[*Node]bool {
	callers := make(map[*Node]bool)
	for _, e := range callee.In {
		callers[e.Caller] = true
	}
	return callers
}

func PathSearchCallTo(start *Node, fn string) Path {
	return PathSearch(start, func(n *Node) bool {
		fnStr := n.Func.String()
		return fnStr == fn
	})
}

func InstructionsFor(root *Node, v ssa.Value) (si ssa.Instruction) {
	PathsSearch(root, func(n *Node) bool {
		for _, b := range root.Func.Blocks {
			for _, instr := range b.Instrs {
				if instr.Pos() == v.Pos() {
					si = instr
					return true
				}
			}
		}
		return false
	})
	return
}

func PathsSearchCallTo(start *Node, fn string) Paths {
	return PathsSearch(start, func(n *Node) bool {
		fnStr := n.Func.String()
		return fnStr == fn
	})
}
