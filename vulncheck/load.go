package vulncheck

import (
	"context"
	"fmt"
	"runtime"
	"slices"
	"strings"

	"github.com/picatz/taint/callgraphutil"
	"github.com/picatz/taint/vulndb"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// LoadConfig configures how Load discovers and builds the program to scan.
type LoadConfig struct {
	// Dir is the directory to scan; the module rooted at or above it is
	// analyzed. Empty means the current working directory.
	Dir string
	// Patterns are the package patterns to load; empty means "./...".
	Patterns []string
	// Tests includes test files and their packages in the scan.
	Tests bool
	// BuildFlags are passed to the underlying go/packages loader (e.g. build
	// tags: []string{"-tags=integration"}).
	BuildFlags []string
	// GoVersion is the toolchain version used to match standard-library and
	// toolchain advisories (e.g. "go1.24.4"). Empty defaults to the version
	// that built the scanner, which is the toolchain that would compile the
	// target.
	GoVersion string
}

// loadMode is the package information the scanner needs: names, files, types,
// imports, and the module of each package for the build list.
const loadMode = packages.NeedName |
	packages.NeedFiles |
	packages.NeedCompiledGoFiles |
	packages.NeedImports |
	packages.NeedDeps |
	packages.NeedTypes |
	packages.NeedSyntax |
	packages.NeedTypesInfo |
	packages.NeedModule

// Load discovers, type-checks, and builds the program under cfg into a Target
// ready to Scan: SSA, a CHA+VTA call graph scoped to the entry points, the
// module build list, and the imported package set. It returns an error when no
// package could be built, and reports type-checking errors from the loaded
// packages so a caller can surface them.
func Load(ctx context.Context, cfg LoadConfig) (*Target, error) {
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
		return nil, fmt.Errorf("vulncheck: loading packages: %w", err)
	}
	if errs := loadErrors(pkgs); len(errs) > 0 {
		return nil, fmt.Errorf("vulncheck: %d package load error(s): %s", len(errs), summarizeErrors(errs))
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("vulncheck: no packages matched %v", patterns)
	}

	prog, _ := ssautil.Packages(pkgs, ssa.InstantiateGenerics)
	prog.Build()

	built := builtPackages(prog)
	entries := entryPoints(built)
	if len(entries) == 0 {
		return nil, fmt.Errorf("vulncheck: no entry points found in %v", patterns)
	}

	// Build the taint engine's own call graph, rooted at the program entry
	// points. Unlike a pure forward slice it connects framework-dispatched
	// closures (an HTTP handler registered as a value, then invoked by the
	// server), which is what lets the taint tier follow real request flows, and
	// it carries the single root the reachability and taint passes both walk.
	cg, _, err := callgraphutil.BuildCallGraph(ctx, callgraphutil.CallGraphAlgorithmTaint, prog, mainRoot(built), entries)
	if err != nil {
		return nil, fmt.Errorf("vulncheck: building call graph: %w", err)
	}

	goVersion := cfg.GoVersion
	if goVersion == "" {
		goVersion = normalizeGoVersion(runtime.Version())
	}

	return &Target{
		Program:          prog,
		CallGraph:        cg,
		Entries:          entries,
		Modules:          buildList(pkgs, goVersion),
		ImportedPackages: importedPackages(pkgs),
	}, nil
}

// loadErrors collects every package and module error from the loaded packages,
// so a caller receives them in the returned error rather than on stderr
// (library code must not write to the process's streams). Module errors are
// reported once per module, matching packages.PrintErrors.
func loadErrors(pkgs []*packages.Package) []string {
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

// normalizeGoVersion reduces a runtime.Version() string to a matchable
// "goX.Y.Z" form. A released toolchain already reports that; a development
// build reports "devel go1.27-abcdef ...", from which the "go1.27" token is
// extracted so standard-library advisories match against a real version rather
// than falling through to the conservative "affects everything" default.
func normalizeGoVersion(v string) string {
	for _, field := range strings.Fields(v) {
		if strings.HasPrefix(field, "go") {
			// Trim a "-abcdef" devel suffix, keeping the goX.Y[.Z] core.
			if i := strings.IndexByte(field, '-'); i >= 0 {
				field = field[:i]
			}
			return field
		}
	}
	return v
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

// buildList extracts the module build list from the loaded packages: every
// distinct module at its resolved version, plus the standard library and
// toolchain keyed to goVersion so stdlib and toolchain advisories can match.
func buildList(pkgs []*packages.Package, goVersion string) []vulndb.Module {
	seen := make(map[string]vulndb.Module)
	var stdlibUsed bool

	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.Module != nil && p.Module.Path != "" {
			mod := p.Module
			// A replaced module reports the replacement's version.
			if mod.Replace != nil {
				mod = mod.Replace
			}
			if _, ok := seen[mod.Path]; !ok {
				seen[mod.Path] = vulndb.Module{Path: mod.Path, Version: mod.Version}
			}
			return
		}
		if isStdlibImportPath(p.PkgPath) {
			stdlibUsed = true
		}
	})

	modules := make([]vulndb.Module, 0, len(seen)+2)
	for _, m := range seen {
		modules = append(modules, m)
	}
	if stdlibUsed {
		modules = append(modules,
			vulndb.Module{Path: vulndb.StdlibModule, Version: goVersion},
			vulndb.Module{Path: vulndb.ToolchainModule, Version: goVersion},
		)
	}
	// Deterministic order: seen is a map, and the build list's order flows
	// through to database queries and finding order.
	slices.SortFunc(modules, func(a, b vulndb.Module) int {
		return strings.Compare(a.Path, b.Path)
	})
	return modules
}

// importedPackages returns the set of package import paths present in the
// build, including transitive dependencies, for the package tier.
func importedPackages(pkgs []*packages.Package) map[string]bool {
	set := make(map[string]bool)
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.PkgPath != "" {
			set[p.PkgPath] = true
		}
	})
	return set
}

// isStdlibImportPath reports whether an import path is part of the standard
// library: its first segment is not domain-qualified and is not the toolchain.
func isStdlibImportPath(importPath string) bool {
	if importPath == "" {
		return false
	}
	first, _, _ := strings.Cut(importPath, "/")
	return !strings.Contains(first, ".") && first != "cmd"
}
