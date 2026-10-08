package wholeprogram

import (
	"sort"

	"golang.org/x/tools/go/packages"
)

// BodyCoverage describes the package inputs to SSA body construction, not
// function reachability or a guarantee that every function has a body.
// Assembly, external declarations, and synthetic functions may lack bodies
// even in selected packages.
type BodyCoverage struct {
	// SelectedPackages are initial package IDs supplied to ssautil.Packages.
	SelectedPackages []string
	// SelectedWithoutModuleIdentity lists selected IDs with missing or incomplete
	// module metadata. Same-module coverage cannot be classified for those inputs.
	SelectedWithoutModuleIdentity []string
	// SameModuleDependencies are imported, unselected package IDs belonging
	// to an initial package's exact module, whether built or omitted.
	SameModuleDependencies []string
	// BuiltSameModuleDependencies are additional packages admitted for SSA bodies.
	BuiltSameModuleDependencies []string
	// AdditionalSyntaxBytes charges each loaded Syntax entry of each added variant.
	AdditionalSyntaxBytes int64
	// OtherDependencies counts remaining unselected dependencies, including
	// other modules, the standard library, and unknown module identities.
	OtherDependencies int
}

// BodyCoverage reports selected and additional body inputs without changing
// roots, graph construction, or source/sink matching. Package IDs are sorted
// and unique, including go/packages test variants. In a workspace, Main alone
// is not sufficient: only modules represented by initial packages qualify.
func (p *Program) BodyCoverage() BodyCoverage {
	var result BodyCoverage
	result.AdditionalSyntaxBytes = p.additionalSyntaxBytes
	for _, pkg := range p.additionalBodyPackages {
		result.BuiltSameModuleDependencies = append(result.BuiltSameModuleDependencies, pkg.ID)
	}
	sort.Strings(result.BuiltSameModuleDependencies)
	selected := make(map[*packages.Package]bool)
	selectedIDs := make(map[string]bool)
	var modules []*packages.Module
	for _, pkg := range p.Packages {
		if pkg == nil {
			continue
		}
		selected[pkg] = true
		selectedIDs[pkg.ID] = true
		if knownModule(pkg.Module) {
			modules = append(modules, pkg.Module)
		}
	}
	for id := range selectedIDs {
		result.SelectedPackages = append(result.SelectedPackages, id)
	}
	unknownSelected := make(map[string]bool)
	for _, pkg := range p.Packages {
		if pkg != nil && !knownModule(pkg.Module) {
			unknownSelected[pkg.ID] = true
		}
	}
	for id := range unknownSelected {
		result.SelectedWithoutModuleIdentity = append(result.SelectedWithoutModuleIdentity, id)
	}
	seen := make(map[string]bool)
	packages.Visit(p.Packages, nil, func(pkg *packages.Package) {
		if selected[pkg] || selectedIDs[pkg.ID] || seen[pkg.ID] {
			return
		}
		seen[pkg.ID] = true
		for _, mod := range modules {
			if sameModule(mod, pkg.Module) {
				result.SameModuleDependencies = append(result.SameModuleDependencies, pkg.ID)
				return
			}
		}
		result.OtherDependencies++
	})
	sort.Strings(result.SelectedPackages)
	sort.Strings(result.SelectedWithoutModuleIdentity)
	sort.Strings(result.SameModuleDependencies)
	return result
}

// A module path alone is insufficient to identify a local checkout. Missing
// directory and go.mod metadata is conservatively treated as unknown.
func knownModule(m *packages.Module) bool {
	return m != nil && m.Path != "" && (m.Dir != "" || m.GoMod != "") &&
		(m.Replace == nil || knownModule(m.Replace))
}

func sameModule(a, b *packages.Module) bool {
	if !knownModule(a) || !knownModule(b) {
		return false
	}
	if a.Path != b.Path || a.Version != b.Version || a.Dir != b.Dir || a.GoMod != b.GoMod {
		return false
	}
	if a.Replace == nil || b.Replace == nil {
		return a.Replace == nil && b.Replace == nil
	}
	return sameModule(a.Replace, b.Replace)
}
