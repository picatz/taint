package vulncheck

import "github.com/picatz/taint/vulndb"

// symbolCatalog indexes the affecting advisories by the questions the tiers
// ask: which symbols to look for in the call graph, which symbol belongs to
// which advisory, and, per advisory, whether it reached package precision in
// the build. It is built once so reachability and taint run a single pass.
type symbolCatalog struct {
	// entries are the affecting advisories, in the order returned by the client.
	entries []*vulndb.Entry
	// byID indexes entries for O(1) lookup during finding assembly.
	byID map[string]*vulndb.Entry
	// symbolOwner maps a fully-qualified symbol id to the advisory occurrences
	// that named it (the same symbol id can appear in more than one advisory).
	symbolOwner map[string][]symbolRef
	// pkgLevel records, per advisory ID, the vulnerable packages that are
	// imported by the build but carry no symbol data (package-tier candidates).
	pkgLevel map[string][]string
	// symbolLevel records, per advisory ID, whether it named any symbol in an
	// imported package (so a symbol-tier attempt is warranted).
	symbolLevel map[string]bool
}

// symbolRef ties a symbol id back to the advisory and package that named it.
type symbolRef struct {
	osv     string
	pkg     string
	module  string
	symbol  string // the advisory's own symbol spelling, for reporting
	fixedAt string
	found   string
}

// buildSymbolCatalog indexes advisories against the set of imported packages.
func buildSymbolCatalog(entries []*vulndb.Entry, imported map[string]bool) *symbolCatalog {
	c := &symbolCatalog{
		entries:     entries,
		byID:        make(map[string]*vulndb.Entry, len(entries)),
		symbolOwner: make(map[string][]symbolRef),
		pkgLevel:    make(map[string][]string),
		symbolLevel: make(map[string]bool),
	}
	for _, e := range entries {
		c.byID[e.ID] = e
		for _, a := range e.Affected {
			es := a.EcosystemSpecific
			if es == nil {
				continue
			}
			for _, imp := range es.Imports {
				if !imported[imp.Path] {
					continue
				}
				if imp.IsWholePackage() {
					c.pkgLevel[e.ID] = append(c.pkgLevel[e.ID], imp.Path)
					continue
				}
				c.symbolLevel[e.ID] = true
				for _, sym := range imp.Symbols {
					for _, id := range vulndb.SymbolSinkIDs(imp.Path, sym) {
						c.symbolOwner[id] = append(c.symbolOwner[id], symbolRef{
							osv:    e.ID,
							pkg:    imp.Path,
							module: a.ModulePath(),
							symbol: sym,
						})
					}
				}
			}
		}
	}
	return c
}

// wantedSymbols returns the set of symbol ids reachability should look for.
func (c *symbolCatalog) wantedSymbols() symbolSet {
	set := make(symbolSet, len(c.symbolOwner))
	for id := range c.symbolOwner {
		set[id] = struct{}{}
	}
	return set
}

// findings assembles the ranked findings from the reachability and taint
// results. Each advisory contributes findings at the highest tier it reached:
// a taint or symbol finding per reached symbol, else a single package finding
// if it imports a vulnerable package, else a single module finding.
func (c *symbolCatalog) findings(target *Target, reached map[string][]Frame, tainted map[string][]string) []Finding {
	var findings []Finding
	// Track which advisories produced a symbol-or-better finding, so the
	// module/package fallback does not double-report them.
	reachedAdvisory := make(map[string]bool)

	// De-duplicate (advisory, symbol) pairs: the two receiver spellings of one
	// method map to the same advisory symbol.
	type symKey struct{ osv, symbol string }
	seen := make(map[symKey]bool)

	for id, trace := range reached {
		for _, ref := range c.symbolOwner[id] {
			key := symKey{ref.osv, ref.symbol}
			if seen[key] {
				continue
			}
			seen[key] = true
			reachedAdvisory[ref.osv] = true

			f := c.baseFinding(ref.osv, ref.module, target)
			f.Package = ref.pkg
			f.Symbol = ref.symbol
			f.Trace = trace
			if steps, ok := tainted[id]; ok {
				f.Tier = TierTaint
				f.TaintTrace = steps
			} else {
				f.Tier = TierSymbol
			}
			findings = append(findings, f)
		}
	}

	// Package-tier and module-tier fallbacks for advisories with no reached
	// symbol.
	for _, e := range c.entries {
		if reachedAdvisory[e.ID] {
			continue
		}
		if pkgs := c.pkgLevel[e.ID]; len(pkgs) > 0 {
			f := c.baseFinding(e.ID, moduleForEntry(e, target), target)
			f.Tier = TierPackage
			f.Package = pkgs[0]
			findings = append(findings, f)
			continue
		}
		// Symbol-level advisory whose package is imported but whose symbol was
		// not reached still warrants a package-tier finding (the vulnerable
		// package is in the build).
		if c.symbolLevel[e.ID] {
			f := c.baseFinding(e.ID, moduleForEntry(e, target), target)
			f.Tier = TierPackage
			f.Package = firstImportedSymbolPackage(e, target)
			findings = append(findings, f)
			continue
		}
		// No package data, or none imported: module tier.
		f := c.baseFinding(e.ID, moduleForEntry(e, target), target)
		f.Tier = TierModule
		findings = append(findings, f)
	}
	return findings
}

// baseFinding fills the module-level fields common to every tier.
func (c *symbolCatalog) baseFinding(osv, module string, target *Target) Finding {
	f := Finding{OSV: osv, Module: module}
	entry := c.entryByID(osv)
	if entry == nil {
		return f
	}
	for _, a := range entry.Affected {
		if a.ModulePath() != module {
			continue
		}
		version := target.versionOf(module)
		f.FoundVersion = version
		f.FixedVersion = a.FixedVersion(version)
		break
	}
	return f
}

func (c *symbolCatalog) entryByID(id string) *vulndb.Entry {
	return c.byID[id]
}

// moduleForEntry picks the affected module of e that the build actually
// depends on, so a module-tier finding names the right module.
func moduleForEntry(e *vulndb.Entry, target *Target) string {
	for _, a := range e.Affected {
		if target.versionOf(a.ModulePath()) != "" || target.hasModule(a.ModulePath()) {
			return a.ModulePath()
		}
	}
	if len(e.Affected) > 0 {
		return e.Affected[0].ModulePath()
	}
	return ""
}

// firstImportedSymbolPackage returns the first vulnerable package of e that the
// build imports, for a package-tier finding on a symbol-level advisory.
func firstImportedSymbolPackage(e *vulndb.Entry, target *Target) string {
	for _, a := range e.Affected {
		if a.EcosystemSpecific == nil {
			continue
		}
		for _, imp := range a.EcosystemSpecific.Imports {
			if target.ImportedPackages[imp.Path] {
				return imp.Path
			}
		}
	}
	return ""
}
