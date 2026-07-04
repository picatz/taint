// Package vulncheck scans Go code for known vulnerabilities from the Go
// vulnerability database and ranks each by how strongly the code is exposed:
// from merely depending on a vulnerable module, up to attacker-controlled data
// reaching the vulnerable symbol.
//
// It answers a strictly stronger question than reachability-only scanners. A
// symbol-reachable finding means a static call path exists to vulnerable code;
// a taint-reachable finding means untrusted input flows into that call, with an
// evidence trace explaining the flow. The tiers degrade gracefully: advisories
// without symbol data still surface at module or package precision, and a
// reachable-but-untainted symbol is reported as such rather than dropped.
package vulncheck

import "github.com/picatz/taint/vulndb"

// Tier is how strongly the scanned code is exposed to a vulnerability. Higher
// tiers are strictly more specific: each implies every lower tier holds.
type Tier int

const (
	// TierModule: the code depends on a vulnerable version of a module. This
	// is the only tier available for the ~79% of advisories that carry no
	// package or symbol data, and the baseline for all findings.
	TierModule Tier = iota
	// TierPackage: the code imports a vulnerable package of the module. Either
	// the advisory names vulnerable packages and one is imported, or it names
	// vulnerable symbols in a package that is imported (but reachability was
	// not established).
	TierPackage
	// TierSymbol: a vulnerable symbol is reachable through the call graph from
	// an entry point. This is govulncheck's headline precision.
	TierSymbol
	// TierTaint: attacker-controlled data reaches a vulnerable symbol. This is
	// the strongest signal, unique to a taint-aware scanner, and carries an
	// evidence trace of the flow.
	TierTaint
)

// String returns the tier's lowercase name.
func (t Tier) String() string {
	switch t {
	case TierModule:
		return "module"
	case TierPackage:
		return "package"
	case TierSymbol:
		return "symbol"
	case TierTaint:
		return "taint"
	default:
		return "unknown"
	}
}

// Frame is one function in a call trace, from an entry point down to a
// vulnerable symbol. Trace[0] is the entry point and the last frame is the
// vulnerable symbol.
type Frame struct {
	// Function is the fully-qualified function or method, e.g.
	// "golang.org/x/text/language.Parse" or "(*net/http.Client).Do".
	Function string `json:"function"`
	// Package is the function's package import path.
	Package string `json:"package,omitempty"`
	// Position is the source position "file:line:col" of the call site, when
	// known.
	Position string `json:"position,omitempty"`
}

// Finding is one vulnerability detected in the scanned code, at the highest
// tier established for it. A single advisory can yield several findings when it
// names multiple vulnerable symbols reached by different paths.
type Finding struct {
	// OSV is the advisory identifier, e.g. "GO-2022-0187".
	OSV string `json:"osv"`
	// Tier is how strongly the code is exposed.
	Tier Tier `json:"tier"`
	// Module is the vulnerable module path (or "stdlib"/"toolchain").
	Module string `json:"module"`
	// FoundVersion is the version in the build that is vulnerable.
	FoundVersion string `json:"found_version,omitempty"`
	// FixedVersion is the version that resolves the vulnerability, when the
	// advisory lists one.
	FixedVersion string `json:"fixed_version,omitempty"`
	// Package is the vulnerable package import path, for package tier and above.
	Package string `json:"package,omitempty"`
	// Symbol is the vulnerable symbol reached, for symbol tier and above,
	// spelled as in the trace's final frame.
	Symbol string `json:"symbol,omitempty"`
	// Trace is the call stack from an entry point to the vulnerable symbol, for
	// symbol tier and above.
	Trace []Frame `json:"trace,omitempty"`
	// TaintTrace explains the tainted-data flow into the symbol, for taint tier.
	// Each entry is a human-readable step in the evidence chain.
	TaintTrace []string `json:"taint_trace,omitempty"`
}

// Result is the outcome of a scan: the findings, ranked, plus the advisories
// they reference for detail rendering.
type Result struct {
	// Findings are the detected vulnerabilities, ranked most-exposed first.
	Findings []Finding `json:"findings"`
	// Entries maps advisory ID to the full advisory, for callers that render
	// summaries, severities, or links.
	Entries map[string]*vulndb.Entry `json:"-"`
}

// tierRank orders findings for presentation: higher tier first, then by OSV ID
// and symbol for stable output.
func lessFinding(a, b Finding) int {
	if a.Tier != b.Tier {
		return int(b.Tier) - int(a.Tier) // higher tier first
	}
	if a.OSV != b.OSV {
		if a.OSV < b.OSV {
			return -1
		}
		return 1
	}
	if a.Symbol != b.Symbol {
		if a.Symbol < b.Symbol {
			return -1
		}
		return 1
	}
	return 0
}
