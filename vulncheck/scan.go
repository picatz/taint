package vulncheck

import (
	"context"
	"slices"

	"github.com/picatz/taint"
	"github.com/picatz/taint/vulndb"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// Target is a loaded program ready to scan: its SSA, a call graph scoped to
// what is reachable from the entry points, the module build list, and the set
// of imported packages. Load produces one from a directory; tests can build one
// directly.
type Target struct {
	// Program is the built SSA program.
	Program *ssa.Program
	// CallGraph is reachable from Entries (a CHA+VTA graph, as govulncheck
	// builds), used for both symbol reachability and the taint tier.
	CallGraph *callgraph.Graph
	// Entries are the reachable roots (main+init, or a library's exported API).
	Entries []*ssa.Function
	// Modules is the build list: every module the program depends on, at its
	// resolved version, including the standard library and toolchain.
	Modules []vulndb.Module
	// ImportedPackages is the set of package import paths present in the build.
	ImportedPackages map[string]bool
}

// versionOf returns the resolved version of the given module in the build, or
// "" when the build does not depend on it.
func (t *Target) versionOf(module string) string {
	for _, m := range t.Modules {
		if m.Path == module {
			return m.Version
		}
	}
	return ""
}

// hasModule reports whether the build depends on the given module.
func (t *Target) hasModule(module string) bool {
	for _, m := range t.Modules {
		if m.Path == module {
			return true
		}
	}
	return false
}

// Scan finds vulnerabilities affecting the target and ranks each by exposure
// tier. It queries src for advisories affecting the build list, then for each
// advisory establishes the highest tier it can: module (depends on a
// vulnerable version), package (imports a vulnerable package), symbol (a
// vulnerable symbol is reachable), or taint (attacker-controlled data reaches
// it). Options tune the taint tier's source set and models.
func Scan(ctx context.Context, target *Target, src vulndb.Source, opts ...Option) (*Result, error) {
	cfg := scanConfig{sources: DefaultSources()}
	for _, opt := range opts {
		opt(&cfg)
	}

	client := vulndb.NewClient(src)
	entries, err := client.AffectingEntries(ctx, target.Modules)
	if err != nil {
		return nil, err
	}

	result := &Result{Entries: make(map[string]*vulndb.Entry, len(entries))}
	for _, e := range entries {
		result.Entries[e.ID] = e
	}

	// Gather every vulnerable symbol across all advisories into one sink set,
	// so reachability and taint each run a single pass over the graph rather
	// than once per advisory.
	catalog := buildSymbolCatalog(entries, target.ImportedPackages)

	// Symbol tier: which vulnerable symbols are reachable, with traces.
	reached := reachableSymbols(target.CallGraph, catalog.wantedSymbols())

	// Taint tier: which reachable symbols receive attacker-controlled data.
	tainted := scanTaint(target, cfg, reached)

	result.Findings = catalog.findings(target, reached, tainted)
	slices.SortStableFunc(result.Findings, lessFinding)
	return result, nil
}

// scanTaint runs taint analysis with the reachable vulnerable symbols as sinks
// and returns, per symbol id, the evidence trace of the first tainted flow into
// it. Only reachable symbols are used as sinks, bounding the work to advisories
// that already cleared the symbol tier.
func scanTaint(target *Target, cfg scanConfig, reached map[string][]Frame) map[string][]string {
	if len(reached) == 0 {
		return nil
	}
	sinkIDs := make([]string, 0, len(reached))
	for id := range reached {
		sinkIDs = append(sinkIDs, id)
	}
	sinks := taint.NewSinks(sinkIDs...)

	checkOpts := cfg.checkOptions()
	diags := taint.CheckDetailed(target.CallGraph, cfg.sources, sinks, checkOpts...)

	tainted := make(map[string][]string)
	for _, d := range diags {
		id := d.Result.SinkType
		if _, ok := reached[id]; !ok {
			continue
		}
		if _, seen := tainted[id]; seen {
			continue
		}
		tainted[id] = taintTrace(d)
	}
	return tainted
}
