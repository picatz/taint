package taint

import (
	"testing"
)

const mapRangeProbeHelpers = `
func source() string { return "user" }
func sink(string) {}
func clean(s string) string { return s }
func flag() bool { return true }
func fill(m map[string]string, s string) { m["q"] = s }
func read(m map[string]string) { for _, v := range m { sink(v) } }
func makeValues(s string) map[string]string { return map[string]string{"q": s} }
`

func TestCheckDetailedMapRange(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"direct_source_control", `sink(source())`, 1},
		{"lookup_control", `m := map[string]string{"q": source()}; sink(m["q"])`, 1},
		{"range_value", `m := map[string]string{"q": source()}; for _, v := range m { sink(v) }`, 1},
		{"range_key", `m := map[string]string{source(): "safe"}; for k := range m { sink(k) }`, 1},
		{"range_both", `m := map[string]string{source(): source()}; for k, v := range m { sink(k); sink(v) }`, 2},
		{"value_through_alias", `m := map[string]string{"q": source()}; a := m; for _, v := range a { sink(v) }`, 1},
		{"named_map", `type M map[string]string; m := M{"q": source()}; for _, v := range m { sink(v) }`, 1},
		{"conditional_write", `m := make(map[string]string); if flag() { m["q"] = source() }; for _, v := range m { sink(v) }`, 1},
		{"one_of_two_keys", `m := map[string]string{"q": source(), "safe": "safe"}; for _, v := range m { sink(v) }`, 1},
		{"tainted_key_clean_value", `m := map[string]string{source(): "safe"}; for _, v := range m { sink(v) }`, 0},
		{"tainted_value_clean_key", `m := map[string]string{"q": source()}; for k := range m { sink(k) }`, 0},
		{"clean_map", `m := map[string]string{"q": "safe"}; for _, v := range m { sink(v) }`, 0},
		{"unrelated_source", `_ = source(); m := map[string]string{"q": "safe"}; for _, v := range m { sink(v) }`, 0},
		{"cleared_before_range", `m := map[string]string{"q": source()}; clear(m); for _, v := range m { sink(v) }`, 0},
		{"deleted_before_range", `m := map[string]string{"q": source()}; delete(m, "q"); for _, v := range m { sink(v) }`, 0},
		{"overwritten_before_range", `m := map[string]string{"q": source()}; m["q"] = "safe"; for _, v := range m { sink(v) }`, 0},
		{"write_after_range", `m := map[string]string{"q": "safe"}; for _, v := range m { sink(v) }; m["q"] = source()`, 0},
		{"write_after_extract_break", `m := map[string]string{"q": "safe"}; for _, v := range m { m["q"] = source(); sink(v); break }`, 0},
		{"constant_output", `m := map[string]string{"q": source()}; for range m { sink("safe") }`, 0},

		// A new entry or an update to a not-yet-visited entry may be seen by
		// a later Next. These are may-flow positives, not claims about the
		// first iteration or an execution order.
		{"addition_during_range", `m := map[string]string{"a": "safe", "b": "safe"}; for _, v := range m { sink(v); m["new"] = source() }`, 1},
		{"update_other_entry_during_range", `m := map[string]string{"a": "safe", "b": "safe"}; for k, v := range m { if k == "a" { m["b"] = source() }; sink(v) }`, 1},
		// Extracted values are copies. Delete/clear cannot retroactively
		// change v, and a new map assigned to m is not the iterated map.
		{"delete_after_extract", `m := map[string]string{"q": source()}; for k, v := range m { delete(m, k); sink(v) }`, 1},
		{"clear_after_extract", `m := map[string]string{"q": source()}; for _, v := range m { clear(m); sink(v) }`, 1},
		{"delete_during_range_nondeterministic_order", `m := map[string]string{"q": source(), "a": "safe"}; for k, v := range m { if k == "a" { delete(m, "q") }; sink(v) }`, 1},
		{"replace_map_after_extract_break", `m := map[string]string{"q": "safe"}; for _, v := range m { m = map[string]string{"q": source()}; sink(v); break }`, 0},
		{"clear_insert_after_extract_break", `m := map[string]string{"q": "safe"}; for _, v := range m { clear(m); m["new"] = source(); sink(v); break }`, 0},
		{"delete_only_tainted_entry", `m := map[string]string{"q": source(), "safe": "safe"}; delete(m, "q"); for _, v := range m { sink(v) }`, 0},
		{"replace_map_before_range", `m := map[string]string{"q": source()}; m = map[string]string{"q": "safe"}; for _, v := range m { sink(v) }`, 0},
		{"sanitized_output", `m := map[string]string{"q": source()}; for _, v := range m { sink(clean(v)) }`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cg, pkg := detailedGraphForSource(t, "package main\n"+mapRangeProbeHelpers+"\nfunc main() {\n"+tc.body+"\n}\n")
			got := CheckDetailed(cg, NewSources(pkg+".source"), NewSinks(pkg+".sink"), WithSanitizers(pkg+".clean"))

			if len(got) != tc.want {
				t.Errorf("got %d diagnostics, want %d", len(got), tc.want)
			}
		})
	}
}

// These are explicit known false negatives, not clean controls. The range
// model deliberately stops at function boundaries instead of falling back to
// whole-map taint or the key-erasing map-lookup helper summaries. Keep the
// semantic expectation separate from current behavior until those summaries
// can retain map identity, selected components, and per-use reaching writes.
func TestCheckDetailedMapRangeHelperLimitations(t *testing.T) {
	for _, tc := range []struct {
		name, body   string
		semanticWant int
	}{
		{"helper_write", `m := make(map[string]string); fill(m, source()); for _, v := range m { sink(v) }`, 1},
		{"helper_read", `read(map[string]string{"q": source()})`, 1},
		{"helper_return", `for _, v := range makeValues(source()) { sink(v) }`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cg, pkg := detailedGraphForSource(t, "package main\n"+mapRangeProbeHelpers+"\nfunc main() {\n"+tc.body+"\n}\n")
			got := CheckDetailed(cg, NewSources(pkg+".source"), NewSinks(pkg+".sink"))
			if len(got) != 0 {
				t.Fatalf("known unsupported helper flow changed: got %d, semantic expectation %d; review and promote this case to the supported suite", len(got), tc.semanticWant)
			}
			t.Logf("known false negative: observed 0, semantic expectation %d", tc.semanticWant)
		})
	}
}
