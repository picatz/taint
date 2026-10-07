package taint

import (
	"context"

	"github.com/picatz/taint/callgraphutil"
	"golang.org/x/tools/go/callgraph"
)

type sinkCallSites map[*callgraph.Edge]struct{}

// indexSinkCallSites matches rules against the reachable graph, visiting each
// node only once. It deliberately uses the existing matchers: callee names
// alone would miss interface invokes, aliases, closures and synthetic wrappers.
// Entries are keyed by rule position, not id, because models may repeat a sink
// id with different argument selectors. No iteration over these maps controls
// the order of paths or diagnostics.
func indexSinkCallSites(ctx context.Context, cg *callgraph.Graph, rules []sinkRule) []sinkCallSites {
	out := make([]sinkCallSites, len(rules))
	if cg == nil || cg.Root == nil || len(rules) == 0 {
		return out
	}
	seen := map[*callgraph.Node]bool{cg.Root: true}
	stack := []*callgraph.Node{cg.Root}
	for len(stack) > 0 {
		if ctx.Err() != nil {
			return out
		}
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, edge := range node.Out {
			if ctx.Err() != nil {
				return out
			}
			if edge == nil || edge.Callee == nil {
				continue
			}
			for i, rule := range rules {
				if ctx.Err() != nil {
					return out
				}
				if rule.matchEdge != nil && rule.matchEdge(edge) {
					if out[i] == nil {
						out[i] = make(sinkCallSites)
					}
					out[i][edge] = struct{}{}
				}
			}
			if !seen[edge.Callee] {
				seen[edge.Callee] = true
				stack = append(stack, edge.Callee)
			}
		}
	}
	return out
}

// findAllSinkCallSitePaths preserves the historical sink-first, Out-edge DFS
// order, including cycle-closing sink edges. Only matching rules enumerate
// paths, and predicate work is already cached in sites. Paths are still
// materialized one rule at a time to avoid retaining every rule's paths at once.
func findAllSinkCallSitePaths(ctx context.Context, cg *callgraph.Graph, sites sinkCallSites) callgraphutil.Paths {
	if cg == nil || cg.Root == nil || len(sites) == 0 {
		return nil
	}
	var paths callgraphutil.Paths
	var stack callgraphutil.Path
	seen := make(map[*callgraph.Node]bool)
	var search func(*callgraph.Node)
	search = func(node *callgraph.Node) {
		if ctx.Err() != nil || node == nil || seen[node] {
			return
		}
		seen[node] = true
		defer delete(seen, node)
		for _, edge := range node.Out {
			if ctx.Err() != nil {
				return
			}
			if edge == nil || edge.Callee == nil {
				continue
			}
			if _, matches := sites[edge]; matches {
				path := make(callgraphutil.Path, len(stack), len(stack)+1)
				copy(path, stack)
				paths = append(paths, append(path, edge))
			}
			stack = append(stack, edge)
			search(edge.Callee)
			stack = stack[:len(stack)-1]
		}
	}
	search(cg.Root)
	return paths
}
