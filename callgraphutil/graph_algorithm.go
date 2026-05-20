package callgraphutil

import (
	"context"
	"fmt"
	"go/types"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// CallGraphAlgorithm names a supported callgraph construction strategy.
type CallGraphAlgorithm string

const (
	// CallGraphAlgorithmTaint uses this package's custom callgraph builder.
	CallGraphAlgorithmTaint CallGraphAlgorithm = "taint"
	// CallGraphAlgorithmVTA uses the CHA+VTA callgraph builder adapted from govulncheck.
	CallGraphAlgorithmVTA CallGraphAlgorithm = "vta"
)

// ParseCallGraphAlgorithm normalizes a user-facing callgraph algorithm name.
func ParseCallGraphAlgorithm(name string) (CallGraphAlgorithm, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "taint", "custom":
		return CallGraphAlgorithmTaint, nil
	case "vta", "vulncheck":
		return CallGraphAlgorithmVTA, nil
	default:
		return "", fmt.Errorf("unsupported callgraph algorithm %q (supported: taint, vta)", name)
	}
}

// BuildCallGraph constructs a graph using the selected algorithm. If root is
// nil, the graph is created with a synthetic multi-root entry point over srcFns.
func BuildCallGraph(ctx context.Context, algorithm CallGraphAlgorithm, prog *ssa.Program, root *ssa.Function, srcFns []*ssa.Function) (*callgraph.Graph, *ssa.Function, error) {
	algorithm, err := ParseCallGraphAlgorithm(string(algorithm))
	if err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	switch algorithm {
	case CallGraphAlgorithmTaint:
		if root != nil {
			cg, err := NewGraphWithContext(ctx, root, srcFns...)
			return cg, root, err
		}
		cg, syntheticRoot, err := CreateMultiRootCallGraph(prog, srcFns)
		return cg, syntheticRoot, err
	case CallGraphAlgorithmVTA:
		return buildVTACallGraph(ctx, prog, root, srcFns)
	default:
		return nil, nil, fmt.Errorf("unsupported callgraph algorithm %q", algorithm)
	}
}

func buildVTACallGraph(ctx context.Context, prog *ssa.Program, root *ssa.Function, srcFns []*ssa.Function) (*callgraph.Graph, *ssa.Function, error) {
	if prog == nil {
		return nil, nil, fmt.Errorf("nil SSA program")
	}

	entries := dedupeFunctions(append([]*ssa.Function(nil), srcFns...))
	if root != nil {
		entries = dedupeFunctions(append(entries, root))
	}
	if len(entries) == 0 {
		return nil, nil, fmt.Errorf("could not create VTA callgraph without entry points")
	}

	cg, err := NewVulncheckCallGraph(ctx, prog, entries)
	if err != nil {
		return nil, nil, err
	}

	if root != nil {
		cg.Root = cg.CreateNode(root)
		Canonicalize(cg)
		return cg, root, nil
	}

	entryPoints := callgraphEntryPoints(srcFns)
	if len(entryPoints) == 0 {
		return nil, nil, fmt.Errorf("could not create VTA callgraph without entry points")
	}

	sig := types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false)
	syntheticRoot := prog.NewFunction("root", sig, "synthetic")
	rootNode := cg.CreateNode(syntheticRoot)
	cg.Root = rootNode
	for _, entry := range entryPoints {
		if entry == nil {
			continue
		}
		callgraph.AddEdge(rootNode, nil, cg.CreateNode(entry))
	}
	DeduplicateEdges(cg)
	Canonicalize(cg)

	return cg, syntheticRoot, nil
}
