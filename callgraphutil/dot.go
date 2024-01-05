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
	b.WriteString("\tgraph [fontname=\"Helvetica\"];\n")
	b.WriteString("\tnode [fontname=\"Helvetica\"];\n")
	b.WriteString("\tedge [fontname=\"Helvetica\"];\n")

	edges := []*callgraph.Edge{}

	// Write nodes.
	for _, n := range g.Nodes {
		b.WriteString(fmt.Sprintf("\t%q [label=%q];\n", fmt.Sprintf("%d", n.ID), n.Func))

		// Add edges
		edges = append(edges, n.Out...)
	}

	// Write edges.
	for _, e := range edges {
		b.WriteString(fmt.Sprintf("\t%q -> %q [label=%q];\n", fmt.Sprintf("%d", e.Caller.ID), fmt.Sprintf("%d", e.Callee.ID), e.Site))
	}

	b.WriteString("}\n")

	return nil
}
