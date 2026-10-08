package taint

// Reference implementation from maintenance checkpoint 4117a8a. Keep discovery
// and sink-first ordering independent from the indexed implementation so tests
// can compare complete diagnostics, including evidence and witness-path ties.

import (
	"fmt"
	"slices"

	"github.com/picatz/taint/callgraphutil"
	"golang.org/x/tools/go/callgraph"
)

func referenceSinkCallSitePaths(cg *callgraph.Graph, sink sinkRule) callgraphutil.Paths {
	if cg == nil || cg.Root == nil {
		return nil
	}

	var paths callgraphutil.Paths
	var stack callgraphutil.Path
	seen := make(map[*callgraph.Node]bool)

	var search func(*callgraph.Node)
	search = func(node *callgraph.Node) {
		if node == nil || seen[node] {
			return
		}
		seen[node] = true
		defer delete(seen, node)

		for _, edge := range node.Out {
			if edge == nil || edge.Callee == nil {
				continue
			}
			if sink.matchEdge != nil && sink.matchEdge(edge) {
				pathCopy := make(callgraphutil.Path, len(stack), len(stack)+1)
				copy(pathCopy, stack)
				pathCopy = append(pathCopy, edge)
				paths = append(paths, pathCopy)
			}
			stack = append(stack, edge)
			search(edge.Callee)
			stack = stack[:len(stack)-1]
		}
	}
	search(cg.Root)

	return paths
}

func referenceCheckDetailed(cg *callgraph.Graph, sources Sources, sinks Sinks, opts ...Option) Diagnostics {
	cfg := defaultCheckConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	rules := newRuleRegistry(sources, sinks, cfg)

	// Select the richest path per (sink callsite position, source type).
	bestByKey := make(map[string]Diagnostic)

	// For each sink given, identify the individual paths from
	// within the callgraph that those sinks can end up as
	// the final node path (the "sink path").
sinks:
	for _, sink := range rules.sinkRules {
		// Stop between sinks when the caller cancels: the per-sink path
		// enumeration is the expensive step, so this bounds a runaway check
		// while still returning the diagnostics gathered so far.
		if cfg.ctx.Err() != nil {
			break
		}

		// Find all call edges that call the sink function
		sinkPaths := referenceSinkCallSitePaths(cg, sink)

		for _, sinkPath := range sinkPaths {
			if sinkPath.Empty() {
				continue
			}
			if cfg.ctx.Err() != nil {
				break sinks
			}

			// Check if the last edge (e.g. a SQL query) used any of the given
			// sources (e.g. user input in an HTTP request) to identify if it
			// was "tainted".
			trace := &traceRecorder{}
			tainted, src, tv := checkPathDetailed(sinkPath, rules, sink, trace)

			if tainted {
				lastEdge := sinkPath.Last()
				if lastEdge == nil || lastEdge.Site == nil || lastEdge.Callee == nil {
					continue
				}
				sinkPos := sinkPathPos(sinkPath)
				key := fmt.Sprintf("%d|%s", sinkPos, src)
				result := Result{
					Path:        clonePath(sinkPath),
					SourceType:  src,
					SourceValue: tv,
					SinkType:    sink.id,
					SinkValue:   lastEdge.Site.Value(),
				}
				if lastEdge.Callee != nil && lastEdge.Callee.Func != nil {
					result.SinkType = lastEdge.Callee.Func.String()
				}
				candidate := Diagnostic{
					Result:   result,
					Evidence: buildDiagnosticEvidence(sinkPath, sink, result, trace.evidence),
				}
				// Prefer richer (longer) paths so parameter mapping across wrappers is preserved
				if prev, ok := bestByKey[key]; !ok || len(candidate.Result.Path) > len(prev.Result.Path) {
					bestByKey[key] = candidate
				}
			}
		}
	}

	// Drain the map into a slice in a deterministic order. Range-over-map
	// gives a fresh permutation each run; using sorted keys here makes the
	// subsequent stable sort idempotent under reordering of equal keys.
	out := make(Diagnostics, 0, len(bestByKey))
	for _, key := range sortedDiagnosticKeys(bestByKey) {
		out = append(out, bestByKey[key])
	}
	slices.SortStableFunc(out, compareDiagnostics)
	return out
}
