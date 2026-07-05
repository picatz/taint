package callgraphutil

import (
	"slices"

	"golang.org/x/tools/go/callgraph"
)

// CalleesOf returns the distinct nodes called by the caller node, in a
// deterministic order.
func CalleesOf(caller *callgraph.Node) Nodes {
	calleesMap := make(map[*callgraph.Node]bool)
	for _, e := range caller.Out {
		calleesMap[e.Callee] = true
	}

	// Convert map to slice.
	calleesSlice := make([]*callgraph.Node, 0, len(calleesMap))
	for callee := range calleesMap {
		calleesSlice = append(calleesSlice, callee)
	}
	slices.SortStableFunc(calleesSlice, nodeCompare)

	return calleesSlice
}

// CallersOf returns the distinct nodes that call the callee node, in a
// deterministic order.
func CallersOf(callee *callgraph.Node) Nodes {
	uniqCallers := make(map[*callgraph.Node]bool)
	for _, e := range callee.In {
		uniqCallers[e.Caller] = true
	}

	// Convert map to slice.
	callersSlice := make(Nodes, 0, len(uniqCallers))
	for caller := range uniqCallers {
		callersSlice = append(callersSlice, caller)
	}
	slices.SortStableFunc(callersSlice, nodeCompare)

	return callersSlice
}
