package callgraphutil

import (
	"context"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// NewVulncheckCallGraph builds a call graph of prog based on VTA analysis,
// straight from the govulncheck project. This is used to demonstrate the
// difference between the call graph built by this package's algorithm and
// govulncheck's algorithm (based on CHA and VTA analysis).
//
// This method is based on the following:
// https://github.com/golang/vuln/blob/7335627909c99e391cf911fcd214badcb8aa6d7d/internal/vulncheck/utils.go#L63
func NewVulncheckCallGraph(ctx context.Context, prog *ssa.Program, entries []*ssa.Function) (*callgraph.Graph, error) {
	entrySlice := make(map[*ssa.Function]bool)
	for _, e := range entries {
		entrySlice[e] = true
	}

	if err := ctx.Err(); err != nil { // cancelled?
		return nil, err
	}
	initial := cha.CallGraph(prog)
	allFuncs := ssautil.AllFunctions(prog)

	fslice := forwardSlice(entrySlice, initial)
	// Keep only actually linked functions.
	pruneSet(fslice, allFuncs)

	if err := ctx.Err(); err != nil { // cancelled?
		return nil, err
	}
	vtaCg := vta.CallGraph(fslice, initial)

	// Repeat the process once more, this time using
	// the produced VTA call graph as the base graph.
	fslice = forwardSlice(entrySlice, vtaCg)
	pruneSet(fslice, allFuncs)

	if err := ctx.Err(); err != nil { // cancelled?
		return nil, err
	}
	cg := vta.CallGraph(fslice, vtaCg)
	cg.DeleteSyntheticNodes()

	return cg, nil
}

// forwardSlice computes the transitive closure of functions forward reachable
// via calls in cg or referred to in an instruction starting from `sources`.
//
// https://github.com/golang/vuln/blob/7335627909c99e391cf911fcd214badcb8aa6d7d/internal/vulncheck/slicing.go#L14
func forwardSlice(sources map[*ssa.Function]bool, cg *callgraph.Graph) map[*ssa.Function]bool {
	seen := make(map[*ssa.Function]bool)
	var visit func(f *ssa.Function)
	visit = func(f *ssa.Function) {
		if seen[f] {
			return
		}
		seen[f] = true

		if n := cg.Nodes[f]; n != nil {
			for _, e := range n.Out {
				if e.Site != nil {
					visit(e.Callee.Func)
				}
			}
		}

		var buf [10]*ssa.Value // avoid alloc in common case
		for _, b := range f.Blocks {
			for _, instr := range b.Instrs {
				for _, op := range instr.Operands(buf[:0]) {
					if fn, ok := (*op).(*ssa.Function); ok {
						visit(fn)
					}
				}
			}
		}
	}
	for source := range sources {
		visit(source)
	}
	return seen
}

// pruneSet removes functions in `set` that are in `toPrune`.
//
// https://github.com/golang/vuln/blob/7335627909c99e391cf911fcd214badcb8aa6d7d/internal/vulncheck/slicing.go#L49
func pruneSet(set, toPrune map[*ssa.Function]bool) {
	for f := range set {
		if !toPrune[f] {
			delete(set, f)
		}
	}
}
