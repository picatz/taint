package callgraphutil

import (
	"encoding/csv"
	"fmt"
	"io"
	"runtime"
	"strings"

	"golang.org/x/tools/go/callgraph"
)

// WriteCSV writes the given callgraph.Graph to the given io.Writer in CSV
// format. This format can be used to generate a visual representation of the
// call graph using many different tools.
func WriteCSV(w io.Writer, g *callgraph.Graph) error {
	cw := csv.NewWriter(w)
	cw.Comma = ','
	defer cw.Flush()

	// Write header.
	if err := cw.Write([]string{
		"source_pkg",
		"source_pkg_go_version",
		"source_pkg_origin",
		"source_func",
		"source_func_name",
		"source_func_signature",
		"target_pkg",
		"target_pkg_go_version",
		"target_pkg_origin",
		"target_func",
		"target_func_name",
		"target_func_signature",
	}); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write edges.
	for _, n := range g.Nodes {
		source, err := getNodeInfo(n)
		if err != nil {
			return fmt.Errorf("failed to get node info: %w", err)
		}

		for _, e := range n.Out {
			target, err := getNodeInfo(e.Callee)
			if err != nil {
				return fmt.Errorf("failed to get node info: %w", err)
			}

			record := []string{}
			record = append(record, source.CSV()...)
			record = append(record, target.CSV()...)

			// Write edge.
			if err := cw.Write(record); err != nil {
				return fmt.Errorf("failed to write edge: %w", err)
			}
		}
	}

	return nil
}

type nodeInfo struct {
	pkgPath          string
	pkgGoVersion     string
	pkgOrigin        string
	pkgFunc          string
	pkgFuncName      string
	pkgFuncSignature string
}

func (n *nodeInfo) CSV() []string {
	return []string{
		n.pkgPath,
		n.pkgGoVersion,
		n.pkgOrigin,
		n.pkgFunc,
		n.pkgFuncName,
		n.pkgFuncSignature,
	}
}

func getNodeInfo(n *callgraph.Node) (*nodeInfo, error) {
	info := &nodeInfo{
		pkgPath:          "unknown",
		pkgGoVersion:     runtime.Version(),
		pkgOrigin:        "unknown",
		pkgFunc:          n.Func.String(),
		pkgFuncName:      n.Func.Name(),
		pkgFuncSignature: n.Func.Signature.String(),
	}

	if n.Func.Pkg != nil {
		info.pkgPath = n.Func.Pkg.Pkg.Path()

		if goVersion := n.Func.Pkg.Pkg.GoVersion(); goVersion != "" {
			info.pkgGoVersion = strings.TrimPrefix(goVersion, "go")
		}
	}

	if strings.Contains(info.pkgPath, ".") {
		info.pkgOrigin = strings.Split(info.pkgPath, "/")[0]
	} else {
		// If the package path doesn't contain a dot, then it's
		// probably a standard library package? This is a pattern
		// I've used and seen elsewhere.
		info.pkgOrigin = "stdlib"
	}

	return info, nil
}
