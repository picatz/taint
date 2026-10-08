package wholeprogram

import (
	"context"
	"fmt"
	"math"
	"sort"

	"golang.org/x/tools/go/packages"
)

// Bodies selects which loaded packages supply SSA bodies. It does not change
// selected roots or source/sink occurrence ownership.
type Bodies string

const (
	BodiesSelected   Bodies = "selected"
	BodiesSameModule Bodies = "same-module"
)

// BodyLimits bounds additional loaded input complexity, not RSS or SSA build
// time. Both limits must be explicitly positive for BodiesSameModule.
type BodyLimits struct {
	MaxAdditionalPackages    int
	MaxAdditionalSyntaxBytes int64
}

func bodyMode(cfg Config, scope Scope) (Bodies, error) {
	mode := cfg.Bodies
	if mode == "" {
		mode = BodiesSelected
	}
	if mode != BodiesSelected && mode != BodiesSameModule {
		return "", fmt.Errorf("unknown bodies mode %q (want selected or same-module)", mode)
	}
	limits := cfg.BodyLimits
	if mode == BodiesSelected {
		if limits != (BodyLimits{}) {
			return "", fmt.Errorf("body limits require bodies=same-module")
		}
	} else {
		if scope != ScopeSelected {
			return "", fmt.Errorf("bodies=same-module requires scope=selected")
		}
		if limits.MaxAdditionalPackages <= 0 || limits.MaxAdditionalSyntaxBytes <= 0 {
			return "", fmt.Errorf("bodies=same-module requires positive max-body-packages and max-body-syntax-bytes")
		}
	}
	return mode, nil
}

// additionalBodies validates the complete expansion before any SSA is created.
// Only identities in this one packages.Load graph are considered.
func additionalBodies(ctx context.Context, selected []*packages.Package, limits BodyLimits) ([]*packages.Package, int64, error) {
	selectedSet := make(map[*packages.Package]bool)
	var modules []*packages.Module
	for _, pkg := range selected {
		if pkg == nil || !knownModule(pkg.Module) {
			return nil, 0, fmt.Errorf("same-module bodies require known selected module identity")
		}
		selectedSet[pkg] = true
		modules = append(modules, pkg.Module)
	}
	seen := make(map[string]*packages.Package)
	var additional []*packages.Package
	var visit func(*packages.Package) error
	visit = func(pkg *packages.Package) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if pkg == nil {
			return fmt.Errorf("nil package in loaded import graph")
		}
		if prior, ok := seen[pkg.ID]; ok {
			if prior != pkg || prior.Types != pkg.Types {
				return fmt.Errorf("inconsistent loaded package identity %q", pkg.ID)
			}
			return nil
		}
		seen[pkg.ID] = pkg
		if !selectedSet[pkg] {
			for _, mod := range modules {
				if sameModule(mod, pkg.Module) {
					additional = append(additional, pkg)
					break
				}
			}
		}
		keys := make([]string, 0, len(pkg.Imports))
		for key := range pkg.Imports {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if err := visit(pkg.Imports[key]); err != nil {
				return err
			}
		}
		return nil
	}
	for _, pkg := range selected {
		if err := visit(pkg); err != nil {
			return nil, 0, fmt.Errorf("planning same-module bodies: %w", err)
		}
	}
	sort.Slice(additional, func(i, j int) bool { return additional[i].ID < additional[j].ID })
	var total int64
	for _, pkg := range additional {
		if err := ctx.Err(); err != nil {
			return nil, 0, fmt.Errorf("accounting same-module bodies: %w", err)
		}
		if pkg.IllTyped || pkg.Types == nil || pkg.TypesInfo == nil || pkg.Fset == nil || len(pkg.Syntax) == 0 || len(pkg.Syntax) != len(pkg.CompiledGoFiles) {
			return nil, 0, fmt.Errorf("same-module body package %q has incomplete syntax or type information", pkg.ID)
		}
		for _, file := range pkg.Syntax {
			if file == nil {
				return nil, 0, fmt.Errorf("same-module body package %q has missing syntax", pkg.ID)
			}
			tokenFile := pkg.Fset.File(file.Pos())
			if tokenFile == nil {
				return nil, 0, fmt.Errorf("same-module body package %q has missing token-file metadata", pkg.ID)
			}
			size := int64(tokenFile.Size())
			if size > math.MaxInt64-total {
				return nil, 0, fmt.Errorf("same-module syntax byte count overflow")
			}
			total += size
		}
	}
	if len(additional) > limits.MaxAdditionalPackages || total > limits.MaxAdditionalSyntaxBytes {
		return nil, 0, fmt.Errorf("same-module body budget exceeded: required %d additional packages and %d syntax bytes; allowed %d packages and %d syntax bytes", len(additional), total, limits.MaxAdditionalPackages, limits.MaxAdditionalSyntaxBytes)
	}
	return additional, total, nil
}
