package callgraphutil

import (
	"bufio"
	"fmt"
	"io"

	"golang.org/x/tools/go/callgraph"
)

// WriteDOT writes the given callgraph.Graph to the given io.Writer in the
// DOT format, which can be used to generate a visual representation of the
// call graph using Graphviz.
func WriteDOT(w io.Writer, g *callgraph.Graph) error {
	b := bufio.NewWriter(w)
	defer b.Flush()

	b.WriteString("digraph callgraph {\n")
	b.WriteString("\tgraph [fontname=\"Helvetica\", overlap=false normalize=true];\n")
	b.WriteString("\tnode [fontname=\"Helvetica\" shape=box];\n")
	b.WriteString("\tedge [fontname=\"Helvetica\"];\n")

	edges := []*callgraph.Edge{}

	// Check if root node exists, if so, write it.
	if g.Root != nil {
		b.WriteString(fmt.Sprintf("\troot = %d;\n", g.Root.ID))
	}

	// Write nodes.
	for _, n := range g.Nodes {
		b.WriteString(fmt.Sprintf("\t%d [label=%q];\n", n.ID, n.Func))

		// Add edges
		edges = append(edges, n.Out...)
	}

	// Write edges.
	for _, e := range edges {
		b.WriteString(fmt.Sprintf("\t%d -> %d;\n", e.Caller.ID, e.Callee.ID))
	}

	b.WriteString("}\n")

	return nil
}
