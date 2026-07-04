package vulncheck

import (
	"fmt"
	"io"
	"strings"

	"github.com/picatz/taint/vulndb"
)

// WriteText renders a scan result as a human-readable report, grouped by
// exposure tier from most to least severe. Taint-tier findings lead with the
// data-flow evidence, symbol-tier findings show the call trace, and module and
// package findings state the dependency to update. A scan with no findings
// writes a single reassuring line.
func WriteText(w io.Writer, res *Result) error {
	bw := &errWriter{w: w}
	if len(res.Findings) == 0 {
		bw.printf("No known vulnerabilities found.\n")
		return bw.err
	}

	counts := tierCounts(res.Findings)
	bw.printf("Found %d vulnerability finding(s): %s.\n\n", len(res.Findings), summarizeCounts(counts))

	for i, f := range res.Findings {
		writeFinding(bw, res, f)
		if i < len(res.Findings)-1 {
			bw.printf("\n")
		}
	}
	return bw.err
}

func writeFinding(bw *errWriter, res *Result, f Finding) {
	entry := res.Entries[f.OSV]

	bw.printf("%s [%s] %s\n", f.OSV, strings.ToUpper(f.Tier.String()), summaryOf(entry))
	bw.printf("  module:  %s", f.Module)
	if f.FoundVersion != "" {
		bw.printf(" @ %s", f.FoundVersion)
	}
	bw.printf("\n")
	if f.FixedVersion != "" {
		bw.printf("  fix:     upgrade to %s\n", f.FixedVersion)
	} else {
		bw.printf("  fix:     no fixed version is available\n")
	}
	if url := advisoryURL(entry, f.OSV); url != "" {
		bw.printf("  more:    %s\n", url)
	}

	switch f.Tier {
	case TierTaint:
		bw.printf("  %s\n", tierExplanation(TierTaint))
		if f.Package != "" && f.Symbol != "" {
			bw.printf("  symbol:  %s.%s\n", f.Package, f.Symbol)
		}
		writeTaintTrace(bw, f)
		writeCallTrace(bw, f)
	case TierSymbol:
		bw.printf("  %s\n", tierExplanation(TierSymbol))
		if f.Package != "" && f.Symbol != "" {
			bw.printf("  symbol:  %s.%s\n", f.Package, f.Symbol)
		}
		writeCallTrace(bw, f)
	case TierPackage:
		bw.printf("  %s\n", tierExplanation(TierPackage))
		if f.Package != "" {
			bw.printf("  package: %s\n", f.Package)
		}
	case TierModule:
		bw.printf("  %s\n", tierExplanation(TierModule))
	}
}

func writeTaintTrace(bw *errWriter, f Finding) {
	if len(f.TaintTrace) == 0 {
		return
	}
	bw.printf("  data flow:\n")
	for _, step := range f.TaintTrace {
		bw.printf("    %s\n", step)
	}
}

func writeCallTrace(bw *errWriter, f Finding) {
	if len(f.Trace) == 0 {
		return
	}
	bw.printf("  call stack:\n")
	for i, frame := range f.Trace {
		indent := strings.Repeat("  ", i)
		bw.printf("    %s%s", indent, frame.Function)
		if frame.Position != "" {
			bw.printf("  (%s)", frame.Position)
		}
		bw.printf("\n")
	}
}

// tierExplanation is the one-line meaning of a finding's tier, phrased for a
// reader deciding how urgently to act.
func tierExplanation(t Tier) string {
	switch t {
	case TierTaint:
		return "attacker-controlled data reaches the vulnerable symbol"
	case TierSymbol:
		return "a vulnerable symbol is reachable from your code"
	case TierPackage:
		return "your build imports a vulnerable package"
	case TierModule:
		return "your build depends on a vulnerable module version"
	default:
		return ""
	}
}

func summaryOf(entry *vulndb.Entry) string {
	if entry == nil {
		return ""
	}
	if entry.Summary != "" {
		return entry.Summary
	}
	// Fall back to the first line of the details.
	if entry.Details != "" {
		if line, _, _ := strings.Cut(entry.Details, "\n"); line != "" {
			return line
		}
	}
	return ""
}

func advisoryURL(entry *vulndb.Entry, id string) string {
	if entry != nil && entry.DatabaseSpecific != nil && entry.DatabaseSpecific.URL != "" {
		return entry.DatabaseSpecific.URL
	}
	if id != "" {
		return "https://pkg.go.dev/vuln/" + id
	}
	return ""
}

func tierCounts(findings []Finding) map[Tier]int {
	counts := make(map[Tier]int)
	for _, f := range findings {
		counts[f.Tier]++
	}
	return counts
}

func summarizeCounts(counts map[Tier]int) string {
	var parts []string
	for _, t := range []Tier{TierTaint, TierSymbol, TierPackage, TierModule} {
		if n := counts[t]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, t))
		}
	}
	return strings.Join(parts, ", ")
}

// errWriter accumulates the first write error so callers can defer the check.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, args ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, args...)
}
