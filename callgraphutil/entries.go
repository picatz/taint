package callgraphutil

import (
	"context"
	"fmt"
	"go/types"
	"slices"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// CreateCallGraphFromEntries builds a custom call graph with a synthetic root
// connected by nil-site edges to exactly the supplied non-nil entries. Entries
// are deduplicated by function identity; synthetic package initializers,
// unexported functions, and closures are accepted without entry-point reselection.
// All entries must belong to prog. A nil program or no non-nil entries is an error.
// The input slice is not modified. On error, no graph or root is returned.
//
// This controls graph roots only, not source/sink eligibility or analysis
// completeness. Like NewGraphWithContext, construction scans functions beyond
// those reachable from the roots and uses the existing call-resolution heuristics;
// it neither loads additional dependency bodies nor limits the graph's Nodes to
// reachable functions. Edge ordering follows Canonicalize; node IDs and map
// iteration order are not stable identifiers.
//
// Cancellation is cooperative: ctx is checked around construction and by
// NewGraphWithContext during its walk, but its all-functions prepass may finish
// before cancellation is observed. The legacy CreateMultiRootCallGraph retains
// its heuristic entry selection and is unaffected by this API.
func CreateCallGraphFromEntries(ctx context.Context, prog *ssa.Program, entries []*ssa.Function) (*callgraph.Graph, *ssa.Function, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if prog == nil {
		return nil, nil, fmt.Errorf("nil SSA program")
	}
	exact := make([]*ssa.Function, 0, len(entries))
	seen := make(map[*ssa.Function]bool, len(entries))
	for _, fn := range entries {
		if fn != nil && !seen[fn] {
			exact = append(exact, fn)
			seen[fn] = true
		}
	}
	if len(exact) == 0 {
		return nil, nil, fmt.Errorf("could not create callgraph without entry points")
	}
	for _, fn := range exact {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if fn.Prog != prog {
			return nil, nil, fmt.Errorf("entry function %s belongs to a different SSA program", fn)
		}
	}
	// Stable walk order avoids making caller input order affect traversal.
	slices.SortStableFunc(exact, func(a, b *ssa.Function) int {
		return nodeCompare(&callgraph.Node{Func: a}, &callgraph.Node{Func: b})
	})
	sig := types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false)
	root := prog.NewFunction("root", sig, "synthetic")
	graph, err := NewGraphWithContext(ctx, root, exact...)
	if err != nil {
		return nil, nil, err
	}
	for _, entry := range exact {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		callgraph.AddEdge(graph.Root, nil, graph.CreateNode(entry))
	}
	DeduplicateEdges(graph)
	Canonicalize(graph)
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	return graph, root, nil
}
