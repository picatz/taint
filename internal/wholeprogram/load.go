// Package wholeprogram loads a Go program in its entirety and builds the taint
// engine's call graph over it, rooted at the program's entry points. It is the
// shared substrate for whole-program analysis: the vulnerability scanner and
// the whole-program detector driver both build on it, so cross-package flows
// (a request handler in one package reaching a sink in another) are visible in
// a single call graph rather than lost at a package boundary the way a
// per-package go/analysis pass loses them.
package wholeprogram

import (
	"context"
	"fmt"
	"go/types"
	"strings"

	"github.com/picatz/taint/callgraphutil"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Scope selects the whole-program analysis profile. The empty value preserves
// the legacy profile. Body availability is configured separately.
type Scope string

const (
	// ScopeLegacy preserves the original roots and unrestricted occurrence matching.
	ScopeLegacy Scope = "legacy"
	// ScopeSelected uses exact selected-package roots and occurrence identities.
	ScopeSelected Scope = "selected"
)

// Config configures how Load discovers and builds the program.
type Config struct {
	// Bodies defaults to selected. Same-module requires ScopeSelected and positive limits.
	Bodies     Bodies
	BodyLimits BodyLimits
	// Scope selects the analysis profile; empty means ScopeLegacy.
	Scope Scope
	// Dir is the directory to load; the module rooted at or above it is
	// analyzed. Empty means the current working directory.
	Dir string
	// Patterns are the package patterns to load; empty means "./...".
	Patterns []string
	// Tests includes test files and their packages in the load.
	Tests bool
	// BuildFlags are passed to the underlying go/packages loader (e.g. build
	// tags: []string{"-tags=integration"}).
	BuildFlags []string
}

// Program is a built whole-program analysis unit: the SSA program, a call
// graph rooted at the entry points, those entry points, and the loaded
// packages the graph was built from.
type Program struct {
	// Bodies and BodyLimits describe the effective body policy.
	Bodies                 Bodies
	BodyLimits             BodyLimits
	additionalBodyPackages []*packages.Package
	additionalSyntaxBytes  int64
	// Scope is the effective analysis profile, with the empty default normalized.
	Scope Scope
	// MatchPackages holds the exact selected type identities in ScopeSelected.
	// It is nil for legacy. Selected-profile consumers must pass these identities
	// to taint.WithMatchPackages; restricting graph roots alone is not sufficient.
	MatchPackages []*types.Package
	// SSA is the built SSA program.
	SSA *ssa.Program
	// CallGraph is reachable from Entries, built with the taint algorithm so
	// framework-dispatched closures (an HTTP handler registered as a value and
	// invoked later by the server) are connected.
	CallGraph *callgraph.Graph
	// Entries are the reachable roots: main and init for a command, or a
	// library's exported API.
	Entries []*ssa.Function
	// Packages are the original selected packages, never the expanded body inputs.
	Packages []*packages.Package
}

// loadMode is the package information whole-program analysis needs: names,
// files, types, imports, and the module of each package.
const loadMode = packages.NeedName |
	packages.NeedFiles |
	packages.NeedCompiledGoFiles |
	packages.NeedImports |
	packages.NeedDeps |
	packages.NeedTypes |
	packages.NeedSyntax |
	packages.NeedTypesInfo |
	packages.NeedModule

// Load discovers, type-checks, and builds the program under cfg, then builds
// the taint call graph over it rooted at the entry points. It reports package
// load and type-check errors in the returned error rather than on stderr, so a
// library caller never writes to the process streams.
func Load(ctx context.Context, cfg Config) (*Program, error) {
	scope := cfg.Scope
	if scope == "" {
		scope = ScopeLegacy
	}
	if scope != ScopeLegacy && scope != ScopeSelected {
		return nil, fmt.Errorf("unknown analysis scope %q (want legacy or selected)", cfg.Scope)
	}
	bodies, err := bodyMode(cfg, scope)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("before loading packages: %w", err)
	}
	patterns := cfg.Patterns
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}
	pkgs, err := packages.Load(&packages.Config{
		Mode:       loadMode,
		Context:    ctx,
		Dir:        cfg.Dir,
		Tests:      cfg.Tests,
		BuildFlags: cfg.BuildFlags,
	}, patterns...)
	if err != nil {
		return nil, fmt.Errorf("loading packages: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("after loading packages: %w", err)
	}
	if errs := LoadErrors(pkgs); len(errs) > 0 {
		return nil, fmt.Errorf("%d package load error(s): %s", len(errs), summarizeErrors(errs))
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("no packages matched %v", patterns)
	}

	inputs := pkgs
	var additional []*packages.Package
	var syntaxBytes int64
	if bodies == BodiesSameModule {
		additional, syntaxBytes, err = additionalBodies(ctx, pkgs, cfg.BodyLimits)
		if err != nil {
			return nil, err
		}
		inputs = append(append([]*packages.Package(nil), pkgs...), additional...)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("before SSA creation: %w", err)
	}
	// SSA creation and Build do not accept a context. Cancellation is checked at
	// their boundaries, but cannot promptly interrupt either operation.
	prog, initial := ssautil.Packages(inputs, ssa.InstantiateGenerics)
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("before SSA build: %w", err)
	}
	prog.Build()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("after SSA build: %w", err)
	}
	initial = initial[:len(pkgs)]

	var built []*ssa.Package
	var entries []*ssa.Function
	var matchPackages []*types.Package
	if scope == ScopeSelected {
		entries = selectedEntryPoints(initial)
		matchPackages = make([]*types.Package, 0, len(pkgs))
		for _, pkg := range pkgs {
			if pkg != nil && pkg.Types != nil {
				matchPackages = append(matchPackages, pkg.Types)
			}
		}
	} else {
		built = builtPackages(prog)
		entries = entryPoints(built)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no entry points found in %v", patterns)
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("before call graph: %w", err)
	}
	var cg *callgraph.Graph
	if scope == ScopeSelected {
		cg, _, err = callgraphutil.CreateCallGraphFromEntries(ctx, prog, entries)
	} else {
		cg, _, err = callgraphutil.BuildCallGraph(ctx, callgraphutil.CallGraphAlgorithmTaint, prog, mainRoot(built), entries)
	}
	if err != nil {
		return nil, fmt.Errorf("building call graph: %w", err)
	}

	return &Program{
		Bodies:                 bodies,
		BodyLimits:             cfg.BodyLimits,
		additionalBodyPackages: additional,
		additionalSyntaxBytes:  syntaxBytes,
		Scope:                  scope,
		MatchPackages:          matchPackages,
		SSA:                    prog,
		CallGraph:              cg,
		Entries:                entries,
		Packages:               pkgs,
	}, nil
}

// LoadErrors collects every package and module error from the loaded packages,
// so a caller receives them in a returned error rather than on stderr. Module
// errors are reported once per module, matching packages.PrintErrors.
func LoadErrors(pkgs []*packages.Package) []string {
	var errs []string
	seenModule := make(map[string]bool)
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			errs = append(errs, e.Error())
		}
		if mod := p.Module; mod != nil && mod.Error != nil && !seenModule[mod.Path] {
			seenModule[mod.Path] = true
			errs = append(errs, fmt.Sprintf("module %s: %s", mod.Path, mod.Error.Err))
		}
	})
	return errs
}

// summarizeErrors joins error strings for a single returned error, keeping the
// first few so a badly broken tree does not produce an unreadable wall.
func summarizeErrors(errs []string) string {
	const maxShown = 10
	if len(errs) <= maxShown {
		return strings.Join(errs, "; ")
	}
	return fmt.Sprintf("%s; and %d more", strings.Join(errs[:maxShown], "; "), len(errs)-maxShown)
}

// builtPackages returns the SSA packages the program built, skipping nils.
func builtPackages(prog *ssa.Program) []*ssa.Package {
	all := prog.AllPackages()
	built := make([]*ssa.Package, 0, len(all))
	for _, p := range all {
		if p != nil {
			built = append(built, p)
		}
	}
	return built
}
