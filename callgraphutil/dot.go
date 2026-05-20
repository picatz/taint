package callgraphutil

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"

	"golang.org/x/tools/go/callgraph"
)

// WriteDOT writes the given callgraph.Graph to the given io.Writer in the
// DOT format, which can be used to generate a visual representation of the
// call graph using Graphviz.
func WriteDOT(w io.Writer, g *callgraph.Graph) error {
	b := bufio.NewWriter(w)
	write := func(s string) error {
		if _, err := b.WriteString(s); err != nil {
			return err
		}
		return nil
	}

	if err := write("digraph callgraph {\n"); err != nil {
		return fmt.Errorf("failed to write dot header: %w", err)
	}
	if err := write("\tgraph [fontname=\"Helvetica\", overlap=false normalize=true];\n"); err != nil {
		return fmt.Errorf("failed to write dot graph attributes: %w", err)
	}
	if err := write("\tnode [fontname=\"Helvetica\" shape=box];\n"); err != nil {
		return fmt.Errorf("failed to write dot node attributes: %w", err)
	}
	if err := write("\tedge [fontname=\"Helvetica\"];\n"); err != nil {
		return fmt.Errorf("failed to write dot edge attributes: %w", err)
	}

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
	if g != nil && g.Root != nil {
		if err := write(fmt.Sprintf("\troot = %d;\n", g.Root.ID)); err != nil {
			return fmt.Errorf("failed to write dot root: %w", err)
		}
	}

	// Process nodes and edges.
	for _, n := range SortedNodes(g) {
		// Add node to map of nodes by package.
		addPkgNode(n)

		// Add edges
		edges = append(edges, sortedOutgoingEdges(n)...)
	}

	// Write nodes by package.
	pkgs := make([]string, 0, len(nodesByPkg))
	for pkg := range nodesByPkg {
		pkgs = append(pkgs, pkg)
	}
	sort.Strings(pkgs)

	for _, pkg := range pkgs {
		nodes := nodesByPkg[pkg]
		// Make the pkg name sugraph cluster friendly (remove dots, dashes, and slashes).
		clusterName := strings.Replace(pkg, ".", "_", -1)
		clusterName = strings.Replace(clusterName, "/", "_", -1)
		clusterName = strings.Replace(clusterName, "-", "_", -1)

		// NOTE: even if we're using a subgraph cluster, it may not be
		// respected by all Graphviz layout engines. For example, the
		// "dot" engine will respect the cluster, but the "sfdp" engine
		// will not.
		if err := write(fmt.Sprintf("\tsubgraph cluster_%s {\n", clusterName)); err != nil {
			return fmt.Errorf("failed to write dot package cluster: %w", err)
		}
		if err := write(fmt.Sprintf("\t\tlabel=%q;\n", pkg)); err != nil {
			return fmt.Errorf("failed to write dot package label: %w", err)
		}
		for _, n := range nodes {
			if err := write(fmt.Sprintf("\t\t%d [label=%q];\n", n.ID, n.Func)); err != nil {
				return fmt.Errorf("failed to write dot node: %w", err)
			}
		}
		if err := write("\t}\n"); err != nil {
			return fmt.Errorf("failed to write dot package cluster close: %w", err)
		}
	}

	// Write edges.
	for _, e := range edges {
		if e == nil || e.Caller == nil || e.Callee == nil {
			continue
		}
		if err := write(fmt.Sprintf("\t%d -> %d;\n", e.Caller.ID, e.Callee.ID)); err != nil {
			return fmt.Errorf("failed to write dot edge: %w", err)
		}
	}

	if err := write("}\n"); err != nil {
		return fmt.Errorf("failed to write dot close: %w", err)
	}
	if err := b.Flush(); err != nil {
		return fmt.Errorf("failed to flush dot: %w", err)
	}

	return nil
}
