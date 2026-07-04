package vulndb

import "strings"

// SinkID is a fully-qualified symbol identifier in the form the taint engine
// and callgraph matcher use: a package function "import/path.Func" or a method
// "(Recv).Method" / "(*Recv).Method". Advisory symbols are package-relative and
// spell pointer receivers without a star, so a single advisory symbol may
// expand to more than one SinkID.
type SinkID = string

// SymbolSinkIDs expands one advisory symbol within a package into the
// fully-qualified sink identifiers it could match. A bare function name
// "Func" becomes "pkg.Func". A method "Recv.Method" becomes both "(pkg.Recv).Method"
// and "(*pkg.Recv).Method", because the advisory does not record whether the
// receiver is a pointer and either spelling may appear at a call site.
func SymbolSinkIDs(pkgPath, symbol string) []SinkID {
	recv, method, isMethod := strings.Cut(symbol, ".")
	if !isMethod {
		return []SinkID{pkgPath + "." + symbol}
	}
	qualified := pkgPath + "." + recv
	return []SinkID{
		"(" + qualified + ")." + method,
		"(*" + qualified + ")." + method,
	}
}

// PackageSinkIDs returns the sink identifiers for an advisory import entry. When
// the entry names symbols, each expands via SymbolSinkIDs. When it names no
// symbols, the package is vulnerable wholesale and PackageSinkIDs returns nil;
// callers treat a symbol-less import as "any call into the package" rather than
// matching specific identifiers.
func PackageSinkIDs(imp Import) []SinkID {
	if len(imp.Symbols) == 0 {
		return nil
	}
	var ids []SinkID
	for _, sym := range imp.Symbols {
		ids = append(ids, SymbolSinkIDs(imp.Path, sym)...)
	}
	return ids
}

// IsWholePackage reports whether an advisory import entry names no symbols, in
// which case the whole package is vulnerable and any call into it matches
// (rather than a specific symbol).
func (imp Import) IsWholePackage() bool {
	return len(imp.Symbols) == 0
}
