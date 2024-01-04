package callgraphutil

import "golang.org/x/tools/go/callgraph"

// CalleesOf returns nodes that are called by the caller node.
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

	return calleesSlice
}

// CallersOf returns nodes that call the callee node.
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

	return callersSlice
}
