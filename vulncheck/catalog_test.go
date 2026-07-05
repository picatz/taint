package vulncheck

import (
	"fmt"
	"testing"

	"github.com/picatz/taint/vulndb"
)

// twoSpellingCatalog builds a catalog for one advisory naming one method, so
// vulndb.SymbolSinkIDs expands it into both receiver spellings.
func twoSpellingCatalog(t *testing.T) (*symbolCatalog, []string) {
	t.Helper()
	entry := &vulndb.Entry{
		ID: "GO-2099-0009",
		Affected: []vulndb.Affected{{
			Package: vulndb.Package{Ecosystem: "Go", Name: "example.com/m"},
			EcosystemSpecific: &vulndb.EcosystemSpecific{Imports: []vulndb.Import{{
				Path:    "example.com/m/pkg",
				Symbols: []string{"T.M"},
			}}},
		}},
	}
	c := buildSymbolCatalog([]*vulndb.Entry{entry}, map[string]bool{"example.com/m/pkg": true})
	ids := vulndb.SymbolSinkIDs("example.com/m/pkg", "T.M")
	if len(ids) < 2 {
		t.Fatalf("SymbolSinkIDs returned %d ids, want 2 receiver spellings", len(ids))
	}
	return c, ids
}

// TestFindingsPreferTaintedSpelling pins the fix for a nondeterministic tier:
// when both receiver spellings of one advisory method are reached but only one
// is tainted, the single deduplicated finding must be TierTaint regardless of
// map iteration order.
func TestFindingsPreferTaintedSpelling(t *testing.T) {
	target := &Target{Modules: []vulndb.Module{{Path: "example.com/m", Version: "v1.0.0"}}}

	for _, taintedIdx := range []int{0, 1} {
		c, ids := twoSpellingCatalog(t)
		reached := map[string][]Frame{
			ids[0]: {{Function: "spelling0"}},
			ids[1]: {{Function: "spelling1"}},
		}
		tainted := map[string][]string{ids[taintedIdx]: {"evidence"}}

		findings := c.findings(target, reached, tainted)
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1 deduplicated: %+v", len(findings), findings)
		}
		f := findings[0]
		if f.Tier != TierTaint {
			t.Errorf("tainted spelling %d: tier = %v, want TierTaint", taintedIdx, f.Tier)
		}
		if len(f.TaintTrace) == 0 {
			t.Errorf("tainted spelling %d: missing taint trace", taintedIdx)
		}
		want := fmt.Sprintf("spelling%d", taintedIdx)
		if len(f.Trace) != 1 || f.Trace[0].Function != want {
			t.Errorf("tainted spelling %d: trace = %+v, want the tainted spelling's trace %q",
				taintedIdx, f.Trace, want)
		}
	}
}

// TestFindingsDeterministicWithoutTaint pins that with two reached spellings
// and no taint, repeated runs produce an identical finding.
func TestFindingsDeterministicWithoutTaint(t *testing.T) {
	target := &Target{Modules: []vulndb.Module{{Path: "example.com/m", Version: "v1.0.0"}}}

	var first Finding
	for i := range 20 {
		c, ids := twoSpellingCatalog(t)
		reached := map[string][]Frame{
			ids[0]: {{Function: "spelling0"}},
			ids[1]: {{Function: "spelling1"}},
		}
		findings := c.findings(target, reached, nil)
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
		if i == 0 {
			first = findings[0]
			continue
		}
		got := findings[0]
		if got.Tier != first.Tier || got.Symbol != first.Symbol ||
			len(got.Trace) != len(first.Trace) || got.Trace[0].Function != first.Trace[0].Function {
			t.Fatalf("run %d produced a different finding: %+v vs %+v", i, got, first)
		}
	}
}
