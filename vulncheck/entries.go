package vulncheck

import (
	"go/types"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// entryPoints selects the functions a scan treats as reachable roots, mirroring
// govulncheck: for a main package, only main and the package initializers (the
// program's real entry); for a library with no main, every exported function
// and method plus package initializers, since any of them may be called by a
// consumer. Restricting main packages to main/init avoids reporting dead
// exported code, while libraries must over-approximate because their callers
// are out of scope.
func entryPoints(pkgs []*ssa.Package) []*ssa.Function {
	var entries []*ssa.Function
	mains := ssautil.MainPackages(pkgs)
	if len(mains) > 0 {
		for _, m := range mains {
			if fn := m.Func("main"); fn != nil {
				entries = append(entries, fn)
			}
			if fn := m.Func("init"); fn != nil {
				entries = append(entries, fn)
			}
		}
		return entries
	}
	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}
		for _, member := range pkg.Members {
			fn, ok := member.(*ssa.Function)
			if !ok {
				continue
			}
			if isLibraryEntry(fn) {
				entries = append(entries, fn)
			}
		}
		// Exported methods are members of their receiver's named type, not
		// package members, so collect them from the type's method set.
		entries = append(entries, exportedMethods(pkg)...)
	}
	return entries
}

// mainRoot returns the single main function to root the call graph at when the
// build has exactly one main package, or nil to root at a synthetic node over
// all entries (a library, or several commands). A single concrete root gives
// the taint tier the most precise reachability.
func mainRoot(pkgs []*ssa.Package) *ssa.Function {
	mains := ssautil.MainPackages(pkgs)
	if len(mains) != 1 {
		return nil
	}
	return mains[0].Func("main")
}

// isLibraryEntry reports whether fn is a plausible entry point of a library:
// an exported, non-synthetic function, or a package initializer.
func isLibraryEntry(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}
	if fn.Synthetic == "package initializer" {
		return true
	}
	if fn.Synthetic != "" || fn.Object() == nil {
		return false
	}
	return fn.Object().Exported()
}

// exportedMethods returns the exported methods declared on named types of pkg,
// which a library consumer could call and which are not package members. Both
// the value and pointer method sets are considered.
func exportedMethods(pkg *ssa.Package) []*ssa.Function {
	var methods []*ssa.Function
	prog := pkg.Prog
	for _, member := range pkg.Members {
		typ, ok := member.(*ssa.Type)
		if !ok || !typ.Object().Exported() {
			continue
		}
		named := typ.Type()
		for _, t := range []types.Type{named, types.NewPointer(named)} {
			mset := prog.MethodSets.MethodSet(t)
			for i := range mset.Len() {
				sel := mset.At(i)
				if !sel.Obj().Exported() {
					continue
				}
				if fn := prog.MethodValue(sel); fn != nil {
					methods = append(methods, fn)
				}
			}
		}
	}
	return methods
}
