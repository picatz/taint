package callgraph

import (
	"context"
	"fmt"
	"go/token"
	"go/types"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// A Graph represents a call graph.
//
// A graph may contain nodes that are not reachable from the root.
// If the call graph is sound, such nodes indicate unreachable
// functions.
type Graph struct {
	sync.RWMutex
	Root  *Node                   // the distinguished root node
	Nodes map[*ssa.Function]*Node // all nodes by function
	debug bool
}

// New returns a new Graph with the specified root node.
func New(root *ssa.Function, srcFns ...*ssa.Function) (*Graph, error) {
	g := &Graph{
		RWMutex: sync.RWMutex{},
		Nodes:   make(map[*ssa.Function]*Node),
		debug:   false, // TODO: make configurable with env variable?
	}
	g.Root = g.CreateNode(root)

	eg, _ := errgroup.WithContext(context.Background())

	// 500 = 5849.241s
	// 10  = 4333.030s
	var (
		logger *log.Logger
		ops    int64
		total  int
	)

	if g.debug {
		logger = log.New(os.Stderr, "callgraph-debug ", log.LstdFlags)
		total = len(srcFns)
	}

	s := semaphore.NewWeighted(10)

	allFns := ssautil.AllFunctions(root.Prog)

	for _, srcFn := range srcFns {
		fn := srcFn
		err := s.Acquire(context.Background(), 1)
		if err != nil {
			return nil, fmt.Errorf("failed to aquite semaphore: %w", err)
		}
		eg.Go(func() error {
			defer s.Release(1)

			if g.debug {
				start := time.Now()
				defer func() {
					ops := atomic.AddInt64(&ops, 1)
					logger.Printf("done processing %v (%v/%v) after %v seconds\n", fn, ops, total, time.Since(start).Seconds())
				}()
			}

			err = g.AddFunction(fn, allFns)
			if err != nil {
				return fmt.Errorf("failed to add src function %v: %w", fn, err)
			}

			for _, block := range fn.DomPreorder() {
				for _, instr := range block.Instrs {
					// debugf("found block instr")
					switch instrt := instr.(type) {
					case *ssa.Call:
						// debugf("found call instr")
						fn, ok := instrt.Call.Value.(*ssa.Function)
						if ok {
							err := g.AddFunction(fn, allFns)
							if err != nil {
								return fmt.Errorf("failed to add src function %v from block instr: %w", fn, err)
							}
						}

						// attempt to link function arguments that are functions
						for a := 0; a < len(instrt.Call.Args); a++ {
							arg := instrt.Call.Args[a]
							switch argt := arg.(type) {
							case *ssa.Function:
								// TODO: check if edge already exists?
								AddEdge(g.CreateNode(fn), instrt, g.CreateNode(argt))
							case *ssa.MakeClosure:
								switch argtFn := argt.Fn.(type) {
								case *ssa.Function:
									AddEdge(g.CreateNode(fn), instrt, g.CreateNode(argtFn))

									// Assumes the anonymous functions are called.
									for _, anFn := range argtFn.AnonFuncs {
										AddEdge(g.CreateNode(fn), instrt, g.CreateNode(anFn))
									}
								}
							}
						}
					}
				}
			}
			return nil
		})
	}

	err := eg.Wait()
	if err != nil {
		return nil, fmt.Errorf("error from errgroup: %w", err)
	}

	return g, nil
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

	// start := time.Now()

	if len(allFns) == 0 {
		allFns = ssautil.AllFunctions(target.Prog)
	}

	// log.Printf("finished loading %d functions for target %v in %v seconds", len(allFns), target, time.Since(start).Seconds())

	// Find all direct calls to function,
	// or a place where its address is taken.
	for progFn := range allFns {
		fn := progFn
		// debugf("checking prog fn %v", fn)
		// log.Printf("strt analyzing %v : blk %d", targetNode, len(fn.Blocks))
		var space [32]*ssa.Value // preallocate
		blocks := fn.DomPreorder()

		for _, block := range blocks {
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
					AddEdge(cg.CreateNode(fn), site, targetNode)
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
	g.Lock()
	defer g.Unlock()
	n, ok := g.Nodes[fn]
	if !ok {
		n = &Node{Func: fn, ID: len(g.Nodes)}
		g.Nodes[fn] = n
		return n
	}
	return n
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
	return fmt.Sprintf("%s --> %s", e.Caller, e.Callee)
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
