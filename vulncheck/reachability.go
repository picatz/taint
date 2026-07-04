package vulncheck

import (
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// symbolSet is a set of fully-qualified symbol identifiers (as produced by
// vulndb.SymbolSinkIDs and by *ssa.Function.String).
type symbolSet map[string]struct{}

func (s symbolSet) has(id string) bool {
	_, ok := s[id]
	return ok
}

// crumb records how a call-graph node was first reached during the forward
// walk: the node it was reached from and the edge taken, so a shortest path
// can be reconstructed.
type crumb struct {
	parent *callgraph.Node
	edge   *callgraph.Edge
}

// reachableSymbols reports, for each vulnerable symbol reachable from the call
// graph's root, a representative call trace from an entry point down to it. It
// walks forward from the root over call edges, recording the shortest path to
// each function, so a matching symbol is reported exactly when a real call
// chain leads to it. The synthetic root frame (present when several entries
// share a graph) is dropped from traces.
func reachableSymbols(cg *callgraph.Graph, want symbolSet) map[string][]Frame {
	if cg == nil || cg.Root == nil || len(want) == 0 {
		return nil
	}

	// Breadth-first walk from the root, remembering the edge each node was
	// first reached through, so a shortest path can be reconstructed.
	trail := map[*callgraph.Node]crumb{cg.Root: {}}
	queue := []*callgraph.Node{cg.Root}
	out := make(map[string][]Frame)

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.Func != nil {
			if id := cur.Func.String(); want.has(id) {
				if _, seen := out[id]; !seen {
					out[id] = buildTrace(trail, cur)
				}
			}
		}
		for _, edge := range cur.Out {
			callee := edge.Callee
			if callee == nil || callee.Func == nil {
				continue
			}
			if _, seen := trail[callee]; seen {
				continue
			}
			trail[callee] = crumb{parent: cur, edge: edge}
			queue = append(queue, callee)
		}
	}
	return out
}

// buildTrace reconstructs the path from the root down to target using the
// breadth-first crumbs, returned entry-first and target-last, with the
// synthetic root frame omitted.
func buildTrace(trail map[*callgraph.Node]crumb, target *callgraph.Node) []Frame {
	// Walk parents up to the root, collecting nodes.
	var chain []*callgraph.Node
	for n := target; n != nil; {
		chain = append(chain, n)
		n = trail[n].parent
	}
	// chain is target..root; reverse into root..target, dropping a synthetic
	// root (a function with no package and the synthetic "root" name).
	frames := make([]Frame, 0, len(chain))
	for i := len(chain) - 1; i >= 0; i-- {
		n := chain[i]
		if isSyntheticRoot(n.Func) {
			continue
		}
		frames = append(frames, frameFor(n.Func, trail[n].edge))
	}
	return frames
}

// isSyntheticRoot reports whether fn is the synthetic multi-root node the taint
// call graph inserts above real entry points.
func isSyntheticRoot(fn *ssa.Function) bool {
	return fn != nil && fn.Synthetic == "synthetic" && fn.Name() == "root"
}

// frameFor builds a trace frame for fn, attributing the call-site position from
// edge when available.
func frameFor(fn *ssa.Function, edge *callgraph.Edge) Frame {
	f := Frame{
		Function: fn.String(),
		Package:  packagePath(fn),
	}
	if edge != nil && edge.Site != nil {
		if pos := edge.Site.Pos(); pos.IsValid() {
			f.Position = fn.Prog.Fset.Position(pos).String()
		}
	}
	return f
}

// packagePath returns the import path of fn's package, or "" for functions with
// no package (e.g. synthetic wrappers). It consults the SSA package first and
// falls back to the declaring object, which carries the package for methods
// whose *ssa.Package is not set.
func packagePath(fn *ssa.Function) string {
	if fn == nil {
		return ""
	}
	if pkg := fn.Package(); pkg != nil && pkg.Pkg != nil {
		return pkg.Pkg.Path()
	}
	if obj := fn.Object(); obj != nil && obj.Pkg() != nil {
		return obj.Pkg().Path()
	}
	return ""
}
