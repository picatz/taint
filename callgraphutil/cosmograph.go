package callgraphutil

import (
	"encoding/csv"
	"fmt"
	"io"

	"golang.org/x/tools/go/callgraph"
)

// WriteComsmograph writes the given callgraph.Graph to the given io.Writer in CSV
// format, which can be used to generate a visual representation of the call
// graph using Comsmograph.
//
// https://cosmograph.app/run/
func WriteCosmograph(graph, metadata io.Writer, g *callgraph.Graph) error {
	graphWriter := csv.NewWriter(graph)
	graphWriter.Comma = ','
	defer graphWriter.Flush()

	metadataWriter := csv.NewWriter(metadata)
	metadataWriter.Comma = ','
	defer metadataWriter.Flush()

	// Write header.
	if err := graphWriter.Write([]string{"source", "target", "site"}); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write metadata header.
	if err := metadataWriter.Write([]string{"id", "pkg", "func"}); err != nil {
		return fmt.Errorf("failed to write metadata header: %w", err)
	}

	// Write edges.
	for _, n := range g.Nodes {
		// TODO: fix this so there's not so many "shared" functions?
		//
		// It is a bit of a hack, but it works for now.
		var pkgPath string
		if n.Func.Pkg != nil {
			pkgPath = n.Func.Pkg.Pkg.Path()
		} else {
			pkgPath = "shared"
		}

		// Write metadata.
		if err := metadataWriter.Write([]string{
			fmt.Sprintf("%d", n.ID),
			pkgPath,
			n.Func.String(),
		}); err != nil {
			return fmt.Errorf("failed to write metadata: %w", err)
		}

		for _, e := range n.Out {
			// Write edge.
			if err := graphWriter.Write([]string{
				fmt.Sprintf("%d", n.ID),
				fmt.Sprintf("%d", e.Callee.ID),
				fmt.Sprintf("%q", e.Site),
			}); err != nil {
				return fmt.Errorf("failed to write edge: %w", err)
			}
		}
	}

	return nil
}
