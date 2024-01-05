package callgraphutil

import (
	"bufio"
	"fmt"
	"io"
	"strings"

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

	nodesByPkg := map[string][]*callgraph.Node{}

	addPkgNode := func(n *callgraph.Node) {
		// TODO: fix this so there's not so many "shared" functions?
		//
		// It is a bit of a hack, but it works for now.
		var pkgPath string
		if n.Func.Pkg != nil {
			pkgPath = n.Func.Pkg.Pkg.Path()
		} else {
			pkgPath = "shared"
		}

		// Check if the package already exists.
		if _, ok := nodesByPkg[pkgPath]; !ok {
			// If not, create it.
			nodesByPkg[pkgPath] = []*callgraph.Node{}
		}
		nodesByPkg[pkgPath] = append(nodesByPkg[pkgPath], n)
	}

	// Check if root node exists, if so, write it.
	if g.Root != nil {
		b.WriteString(fmt.Sprintf("\troot = %d;\n", g.Root.ID))
	}

	// Process nodes and edges.
	for _, n := range g.Nodes {
		// Add node to map of nodes by package.
		addPkgNode(n)

		// Add edges
		edges = append(edges, n.Out...)
	}

	// Write nodes by package.
	for pkg, nodes := range nodesByPkg {
		// Make the pkg name sugraph cluster friendly (remove dots, dashes, and slashes).
		clusterName := strings.Replace(pkg, ".", "_", -1)
		clusterName = strings.Replace(clusterName, "/", "_", -1)
		clusterName = strings.Replace(clusterName, "-", "_", -1)

		// NOTE: even if we're using a subgraph cluster, it may not be
		// respected by all Graphviz layout engines. For example, the
		// "dot" engine will respect the cluster, but the "sfdp" engine
		// will not.
		b.WriteString(fmt.Sprintf("\tsubgraph cluster_%s {\n", clusterName))
		b.WriteString(fmt.Sprintf("\t\tlabel=%q;\n", pkg))
		for _, n := range nodes {
			b.WriteString(fmt.Sprintf("\t\t%d [label=%q];\n", n.ID, n.Func))
		}
		b.WriteString("\t}\n")
	}

	// Write edges.
	for _, e := range edges {
		b.WriteString(fmt.Sprintf("\t%d -> %d;\n", e.Caller.ID, e.Callee.ID))
	}

	b.WriteString("}\n")

	return nil
}
