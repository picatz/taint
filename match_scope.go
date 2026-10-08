package taint

import (
	"go/types"
	"strings"

	"github.com/picatz/taint/callgraphutil"
	"golang.org/x/tools/go/ssa"
)

// WithMatchPackages restricts new source matches and sink callsites to SSA
// occurrences owned by the given packages. Package identities must come from
// the same types/SSA program as the call graph. Declaration packages of called
// functions and modeled types do not determine occurrence ownership.
//
// Omitting this option preserves unrestricted matching. An explicitly empty
// list matches no sources or sinks; nil entries are ignored. Repeated options
// replace the earlier scope. The supplied list is copied when creating the
// option. Traversal, return summaries, propagation and sanitizers are unchanged:
// data originating in scope can still flow through functions outside scope.
//
// Lexical closures and generic instances use their declaring function's package.
// Method adapters use their incoming call on the active analysis path. Other
// synthetic functions without a provable lexical owner are excluded; this
// option does not infer ownership from filenames, receivers, or graph roots.
func WithMatchPackages(packages ...*types.Package) Option {
	selected := make(map[*types.Package]struct{}, len(packages))
	for _, pkg := range packages {
		if pkg != nil {
			selected[pkg] = struct{}{}
		}
	}
	return func(cfg *checkConfig) { cfg.matchPackages = selected }
}

func (ctx taintContext) matchesOccurrence(path callgraphutil.Path, v ssa.Value) bool {
	if ctx.matchPackages == nil {
		return true
	}
	return v != nil && occurrenceInPackagesOnPath(v.Parent(), path, ctx.matchPackages)
}

func occurrenceInPackages(fn *ssa.Function, selected map[*types.Package]struct{}) bool {
	if selected == nil {
		return true
	}
	seen := map[*ssa.Function]bool{}
	for fn != nil && !seen[fn] {
		seen[fn] = true
		if parent := fn.Parent(); parent != nil {
			fn = parent
			continue
		}
		if origin := fn.Origin(); origin != nil && origin != fn {
			fn = origin
			continue
		}
		// Wrappers and thunks can borrow the modeled declaration's package;
		// that is not evidence of the source-level occurrence's ownership.
		if fn.Synthetic != "" && !isPackageInitializer(fn) {
			return false
		}
		if fn.Pkg == nil || fn.Pkg.Pkg == nil {
			return false
		}
		_, ok := selected[fn.Pkg.Pkg]
		return ok
	}
	return false
}

// sinkPathInPackages runs before inspecting sink arguments, not as a finding
// filter. Indexing still visits the whole graph, including unselected helpers.
func sinkPathInPackages(path callgraphutil.Path, selected map[*types.Package]struct{}) bool {
	if selected == nil {
		return true
	}
	edge := path.Last()
	return edge != nil && edge.Site != nil && occurrenceInPackagesOnPath(edge.Site.Parent(), path, selected)
}

// The SSA library moves method-value, method-expression and promoted calls into
// compiler-created forwarding functions. Their declaration package is not the
// occurrence package. Resolve only these known adapters using an actual incoming
// call on this witness/return-summary path; an ownerless adapter root is unknown.
func occurrenceInPackagesOnPath(fn *ssa.Function, path callgraphutil.Path, selected map[*types.Package]struct{}) bool {
	if selected == nil {
		return true
	}
	for fn != nil {
		if !isOccurrenceAdapter(fn) {
			return occurrenceInPackages(fn, selected)
		}
		found := false
		for i := len(path) - 1; i >= 0; i-- {
			edge := path[i]
			if edge != nil && edge.Callee != nil && edge.Callee.Func == fn && edge.Site != nil {
				fn = edge.Site.Parent()
				path = path[:i]
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return false
}

func isOccurrenceAdapter(fn *ssa.Function) bool {
	if fn == nil || fn.Syntax() != nil {
		return false
	}
	obj, ok := fn.Object().(*types.Func)
	if !ok || obj == nil {
		return false
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	return strings.HasPrefix(fn.Synthetic, "bound method wrapper for ") || strings.HasPrefix(fn.Synthetic, "thunk for ") || strings.HasPrefix(fn.Synthetic, "wrapper for ")
}

// Package initialization has a unique, directly recorded package owner despite
// its synthetic SSA label; it is not an adapter to a foreign declaration.
func isPackageInitializer(fn *ssa.Function) bool {
	return fn != nil && fn.Synthetic == "package initializer" && fn.Pkg != nil && fn.Pkg.Func("init") == fn
}
