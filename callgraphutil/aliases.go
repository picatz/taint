package callgraphutil

import "golang.org/x/tools/go/callgraph"

// Nodes is a handy alias for a slice of callgraph.Nodes.
type Nodes = []*callgraph.Node

// Edges is a handy alias for a slice of callgraph.Edges.
type Edges = []*callgraph.Edge
