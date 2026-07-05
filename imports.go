package taint

import (
	"go/types"
	"slices"
	"strings"
)

// ImportsAny reports whether pkg imports any of the given package paths,
// directly or transitively. A path matches itself or any of its subpackages
// ("net/http" matches "net/http" and "net/http/httptest").
//
// Detectors use this as a cheap gate: a package that cannot reach any of the
// packages its models describe cannot contain a matching flow, so analysis is
// skipped. The walk must be transitive, or a package reaching a modeled
// package only through an internal helper would be silently skipped, dropping
// real cross-package flows.
func ImportsAny(pkg *types.Package, paths ...string) bool {
	visited := make(map[*types.Package]bool)
	var walk func(*types.Package) bool
	walk = func(p *types.Package) bool {
		if p == nil || visited[p] {
			return false
		}
		visited[p] = true
		for _, path := range paths {
			if p.Path() == path || strings.HasPrefix(p.Path(), path+"/") {
				return true
			}
		}
		return slices.ContainsFunc(p.Imports(), walk)
	}
	return walk(pkg)
}
