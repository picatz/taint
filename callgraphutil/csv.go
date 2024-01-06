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
		"target_pkg",
		"target_pkg_go_version",
		"target_pkg_origin",
		"target_func",
		"target_func_name",
	}); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write edges.
	for _, n := range g.Nodes {

		var (
			sourcePkg string
			targetPkg string

			sourceFunc string
			targetFunc string

			sourceFuncName string
			targetFuncName string

			sourcePkgOrigin string = "unknown"
			targetPkgOrigin string = "unknown"

			runtimeGoVersion   string = runtime.Version()
			sourcePkgGoVersion string = runtimeGoVersion
			targetPkgGoVersion string = runtimeGoVersion
		)

		if n.Func.Pkg != nil {
			sourcePkg, sourcePkgGoVersion, sourcePkgOrigin, sourceFunc, sourceFuncName = nodeCSVInfo(n)
		}

		for _, e := range n.Out {
			targetPkg, targetPkgGoVersion, targetPkgOrigin, targetFunc, targetFuncName = nodeCSVInfo(e.Callee)

			// Write edge.
			if err := cw.Write([]string{
				sourcePkg,
				sourcePkgGoVersion,
				sourcePkgOrigin,
				sourceFunc,
				sourceFuncName,
				targetPkg,
				targetPkgGoVersion,
				targetPkgOrigin,
				targetFunc,
				targetFuncName,
			}); err != nil {
				return fmt.Errorf("failed to write edge: %w", err)
			}
		}
	}

	return nil
}

func nodeCSVInfo(n *callgraph.Node) (
	pkgPath string,
	pkgGoVersion string,
	pkgOrigin string,
	pkgFunc string,
	pkgFuncName string,
) {
	pkgPath = "unknown"
	pkgGoVersion = runtime.Version()
	pkgOrigin = "unknown"
	pkgFunc = n.Func.String()
	pkgFuncName = n.Func.Name()

	if n.Func.Pkg != nil {
		pkgPath = n.Func.Pkg.Pkg.Path()

		if goVersion := n.Func.Pkg.Pkg.GoVersion(); goVersion != "" {
			pkgGoVersion = goVersion
		}
	}

	if strings.Contains(pkgPath, ".") {
		pkgOrigin = strings.Split(pkgPath, "/")[0]
	} else {
		// If the package path doesn't contain a dot, then it's probably a
		// standard library package?
		pkgOrigin = "stdlib"
	}

	return
}
