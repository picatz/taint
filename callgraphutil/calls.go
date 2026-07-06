package callgraphutil

import (
	"maps"
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

	callees := Nodes(slices.Collect(maps.Keys(calleesMap)))
	slices.SortFunc(callees, nodeCompare)

	return callees
}

// CallersOf returns the distinct nodes that call the callee node, in a
// deterministic order.
func CallersOf(callee *callgraph.Node) Nodes {
	uniqCallers := make(map[*callgraph.Node]bool)
	for _, e := range callee.In {
		uniqCallers[e.Caller] = true
	}

	callers := Nodes(slices.Collect(maps.Keys(uniqCallers)))
	slices.SortFunc(callers, nodeCompare)

	return callers
}
