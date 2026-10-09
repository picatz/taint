package taint

import (
	"reflect"
	"testing"

	"golang.org/x/tools/go/ssa"
)

const mapRangeBoundaryHelpers = `
func source() string { return "input" }
func sink(string) {}
func flag() bool { return true }
func setPointer(p *string, s string) { *p = s }
`

func mapRangeBoundaryProgram(body string) string {
	return "package main\n" + mapRangeBoundaryHelpers + "\nfunc main() {\n" + body + "\n}\n"
}

// These cases require only local maps. Unknown conditionals are deliberately
// may-flow cases: a clean alternative must not erase a feasible tainted one.
func TestCheckDetailedMapRangeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"alias_write", `m := make(map[string]string); a := m; a["q"] = source(); for _, v := range m { sink(v) }`, 1},
		{"alias_clear", `m := map[string]string{"q": source()}; a := m; clear(a); for _, v := range m { sink(v) }`, 0},
		{"alias_other_map", `m := map[string]string{"q": "safe"}; other := map[string]string{"q": source()}; a := other; a["x"] = source(); for _, v := range m { sink(v) }`, 0},
		{"interface_alias", `m := map[string]string{"q": "safe"}; var boxed any = m; a := boxed.(map[string]string); a["q"] = source(); for _, v := range m { sink(v) }`, 1},
		{"interface_comma_ok_alias", `m := map[string]string{"q": "safe"}; var boxed any = m; a, ok := boxed.(map[string]string); if ok { a["q"] = source() }; for _, v := range m { sink(v) }`, 1},
		{"interface_comma_ok_range", `m := map[string]string{"q": source()}; var boxed any = m; a, ok := boxed.(map[string]string); if ok { for _, v := range a { sink(v) } }`, 1},
		{"unresolved_sibling_fields", `h := &struct{ a, b map[string]string }{a: map[string]string{"q": source()}, b: map[string]string{"q": "safe"}}; for _, v := range h.b { sink(v) }`, 0},
		{"phi_range", `m := map[string]string{"q": source()}; if flag() { m = map[string]string{"q": "safe"} }; for _, v := range m { sink(v) }`, 1},
		{"phi_clean_range", `m := map[string]string{"q": "safe"}; if flag() { m = map[string]string{"q": "also safe"} }; _ = source(); for _, v := range m { sink(v) }`, 0},
		{"phi_alias_write", `m := map[string]string{"q": "safe"}; a := map[string]string{"q": "safe"}; if flag() { a = m }; a["q"] = source(); for _, v := range m { sink(v) }`, 1},
		{"phi_alias_clear_is_weak", `m := map[string]string{"q": source()}; a := map[string]string{"q": "safe"}; if flag() { a = m }; clear(a); for _, v := range m { sink(v) }`, 1},
		{"phi_alias_overwrite_is_weak", `m := map[string]string{"q": source()}; a := map[string]string{"q": "safe"}; if flag() { a = m }; a["q"] = "safe"; for _, v := range m { sink(v) }`, 1},
		{"named_conversion_write", `type M map[string]string; m := M{"q": "safe"}; a := map[string]string(m); a["q"] = source(); for _, v := range m { sink(v) }`, 1},
		{"named_conversion_clear", `type M map[string]string; m := M{"q": source()}; clear(map[string]string(m)); for _, v := range m { sink(v) }`, 0},
		{"named_key_value_isolation", `type K string; type V string; m := map[K]V{K(source()): "safe"}; for _, v := range m { sink(string(v)) }`, 0},
		{"named_key", `type K string; type V string; m := map[K]V{K(source()): "safe"}; for k := range m { sink(string(k)) }`, 1},
		{"nil", `var m map[string]string; _ = source(); for k, v := range m { sink(k); sink(v) }`, 0},
		{"empty", `m := make(map[string]string); _ = source(); for k, v := range m { sink(k); sink(v) }`, 0},
		{"replace_with_nil", `m := map[string]string{"q": source()}; m = nil; for k, v := range m { sink(k); sink(v) }`, 0},
		{"conditional_delete", `m := map[string]string{"q": source()}; if flag() { delete(m, "q") }; for _, v := range m { sink(v) }`, 1},
		{"all_branches_delete", `m := map[string]string{"q": source()}; if flag() { delete(m, "q") } else { clear(m) }; for _, v := range m { sink(v) }`, 0},
		{"delete_dynamic_key_is_weak", `m := map[string]string{"q": source()}; delete(m, source()); for _, v := range m { sink(v) }`, 1},
		{"same_dynamic_key_overwrite", `k := source(); m := map[string]string{k: source()}; m[k] = "safe"; for _, v := range m { sink(v) }`, 0},
		{"same_dynamic_key_delete", `k := source(); m := map[string]string{k: source()}; delete(m, k); for _, v := range m { sink(v) }`, 0},
		// A dynamic key is not necessarily reflexive. In particular, using
		// the same SSA value for a NaN key does not establish a definite kill.
		{"nan_key_overwrite_is_weak", `k := float64(0); k /= k; m := map[float64]string{k: source()}; m[k] = "safe"; for _, v := range m { sink(v) }`, 1},
		{"nan_key_delete_is_weak", `k := float64(0); k /= k; m := map[float64]string{k: source()}; delete(m, k); for _, v := range m { sink(v) }`, 1},
		{"interface_nan_key_delete_is_weak", `f := float64(0); f /= f; var k any = f; m := map[any]string{k: source()}; delete(m, k); for _, v := range m { sink(v) }`, 1},
		{"struct_nan_key_delete_is_weak", `f := float64(0); f /= f; k := struct{ f float64 }{f}; m := map[struct{ f float64 }]string{k: source()}; delete(m, k); for _, v := range m { sink(v) }`, 1},
		{"array_nan_key_delete_is_weak", `f := float64(0); f /= f; k := [1]float64{f}; m := map[[1]float64]string{k: source()}; delete(m, k); for _, v := range m { sink(v) }`, 1},
		{"interface_distinct_integer_types_delete", `m := map[any]string{int(1): source()}; delete(m, int64(1)); for _, v := range m { sink(v) }`, 1},
		{"interface_distinct_integer_types_overwrite", `m := map[any]string{int(1): source()}; m[int64(1)] = "safe"; for _, v := range m { sink(v) }`, 1},
		{"interface_distinct_named_types_delete", `type K string; m := map[any]string{K("q"): source()}; delete(m, "q"); for _, v := range m { sink(v) }`, 1},
		{"interface_same_type_delete_control", `m := map[any]string{int64(1): source()}; delete(m, int64(1)); for _, v := range m { sink(v) }`, 0},
		// The key definition is the same SSA instruction, but reexecuting it
		// on an outer-loop backedge produces a different runtime key. The
		// prior iteration's entry can survive the next iteration's update.
		{"loop_varying_key_delete_is_weak", `m := make(map[string]string); for i := 0; i < 2; i++ { k := string(rune(i)); delete(m, k); for _, v := range m { sink(v) }; m[k] = source() }`, 1},
		{"loop_varying_key_overwrite_is_weak", `m := make(map[string]string); for i := 0; i < 2; i++ { k := string(rune(i)); m[k] = "safe"; for _, v := range m { sink(v) }; m[k] = source() }`, 1},
		{"other_entry_overwrite", `m := map[string]string{"q": source(), "r": "safe"}; m["r"] = "clean"; for _, v := range m { sink(v) }`, 1},
		{"nested_loop_backedge", `m := map[string]string{"q": "safe"}; for flag() { for _, v := range m { sink(v); break }; m["q"] = source() }`, 1},
		{"nested_loop_clear", `m := map[string]string{"q": source()}; for flag() { clear(m); m["safe"] = "safe"; for _, v := range m { sink(v) }; m["q"] = source() }`, 0},
		// A repeated SSA allocation denotes a fresh runtime map on each outer
		// iteration. The write after the inner break cannot flow into that
		// iteration's already extracted value or the next fresh map.
		{"nested_fresh_allocation", `for flag() { m := map[string]string{"q": "safe"}; for _, v := range m { m["q"] = source(); sink(v); break } }`, 0},
		// A saved Phi can retain the previous allocation's runtime instance;
		// making another map does not clear the saved old map.
		{"fresh_allocation_old_map_retained_phi", `var saved map[string]string; for i := 0; i < 2; i++ { m := map[string]string{"q": "safe"}; for _, v := range saved { sink(v) }; m["q"] = source(); saved = m }`, 1},
		{"fresh_allocation_old_map_retained_phi_key", `var saved map[string]string; for i := 0; i < 2; i++ { m := make(map[string]string); for k := range saved { sink(k) }; m[source()] = "safe"; saved = m }`, 1},
		{"two_branch_maps_retained_phi", `var saved map[string]string; for i := 0; i < 2; i++ { m := map[string]string{"q": "safe"}; if i == 1 { for _, v := range saved { sink(v) } }; m["q"] = source(); saved = m }`, 1},
		{"nested_other_map", `outer := map[string]string{"q": source()}; inner := map[string]string{"q": "safe"}; for range outer { for _, v := range inner { sink(v) } }`, 0},
		{"pointer_value", `p := new(string); *p = source(); m := map[string]*string{"q": p}; for _, v := range m { sink(*v) }`, 1},
		{"pointer_clean_value_tainted_key", `p := new(string); *p = "safe"; m := map[string]*string{source(): p}; for _, v := range m { sink(*v) }`, 0},
		{"pointer_value_clean_key", `p := new(string); *p = source(); m := map[string]*string{"q": p}; for k := range m { sink(k) }`, 0},
		{"pointer_key_clean_pointee_tainted_value", `p := new(string); *p = "safe"; m := map[*string]string{p: source()}; for k := range m { sink(*k) }`, 0},
		{"named_pointer_clean_value_tainted_key", `type P *string; p := new(string); *p = "safe"; m := map[string]P{source(): P(p)}; for _, v := range m { sink(*v) }`, 0},
		{"pointer_source_before_overwrite", `p := new(string); *p = source(); m := map[string]*string{"q": p}; q := new(string); *q = "safe"; m["q"] = q; for _, v := range m { sink(*v) }`, 0},
		{"pointer_source_after_overwrite", `p := new(string); *p = "safe"; m := map[string]*string{"q": p}; q := new(string); *q = source(); m["q"] = q; for _, v := range m { sink(*v) }`, 1},
		{"pointer_unrelated_pointee", `p := new(string); *p = "safe"; other := new(string); *other = source(); m := map[string]*string{"q": p}; for _, v := range m { sink(*v) }`, 0},
		// Unlike strings, pointer elements still refer to mutable pointees.
		{"pointer_write_after_extract", `p := new(string); *p = "safe"; m := map[string]*string{"q": p}; for _, v := range m { *p = source(); sink(*v); break }`, 1},
		{"pointer_write_after_dereference", `p := new(string); *p = "safe"; m := map[string]*string{"q": p}; for _, v := range m { sink(*v); *p = source(); break }`, 0},
		{"pointer_clean_before_dereference", `p := new(string); *p = source(); m := map[string]*string{"q": p}; for _, v := range m { *p = "safe"; sink(*v); break }`, 0},
		{"pointer_helper_write_after_extract", `p := new(string); *p = "safe"; m := map[string]*string{"q": p}; for _, v := range m { setPointer(v, source()); sink(*v); break }`, 1},
		{"pointer_clean_through_extract_multiple_entries", `p := new(string); q := new(string); *p = source(); *q = source(); m := map[string]*string{"p": p, "q": q}; for _, v := range m { *v = "safe"; sink(*v) }`, 0},
		{"pointer_deleted_entry_retains_pointee", `p := new(string); *p = source(); m := map[string]*string{"q": p}; for k, v := range m { delete(m, k); sink(*v); break }`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cg, pkg := detailedGraphForSource(t, mapRangeBoundaryProgram(tc.body))
			sources, sinks := NewSources(pkg+".source"), NewSinks(pkg+".sink")
			got := CheckDetailed(cg, sources, sinks)
			if len(got) != tc.want {
				t.Fatalf("got %d diagnostics, want %d", len(got), tc.want)
			}
			if !reflect.DeepEqual(got, CheckDetailed(cg, sources, sinks)) {
				t.Fatal("repeated check changed diagnostics or evidence")
			}
			for _, d := range got {
				if d.Result.SourceType != pkg+".source" || d.Result.SourceValue == nil || d.Result.SourceValue.String() != pkg+".source" {
					t.Fatalf("wrong source attribution: %+v", d.Result)
				}
				if d.Result.SinkType != pkg+".sink" || !d.Result.ReportPos().IsValid() {
					t.Fatalf("wrong sink attribution: %+v", d.Result)
				}
				assertEvidenceOrder(t, evidenceKinds(d.Evidence), EvidenceSourceMatch, EvidenceSinkMatch)
			}
		})
	}
}

// These are known precision limits, not supported clean or tainted controls.
// Four pointer-alias flows are inherited false negatives in the general pointee
// fallback. A Phi-selected map's clear is a weak kill, so even a definite clear
// through the same Phi currently leaves a conservative false positive. Keep
// semantic expectations visible and promote cases when the limitation changes.
func TestCheckDetailedMapRangeAliasLimitations(t *testing.T) {
	for _, tc := range []struct {
		name, body             string
		observed, semanticWant int
	}{
		{"pointer_helper_write_before_range", `p := new(string); *p = "safe"; m := map[string]*string{"q": p}; setPointer(p, source()); for _, v := range m { sink(*v) }`, 0, 1},
		{"pointer_phi_alias_store", `p := new(string); q := new(string); *p = "safe"; *q = "safe"; a := q; if flag() { a = p }; *a = source(); m := map[string]*string{"p": p}; for _, v := range m { sink(*v) }`, 0, 1},
		{"pointer_prior_range_store", `p := new(string); *p = "safe"; m := map[string]*string{"p": p}; for _, w := range m { *w = source() }; for _, v := range m { sink(*v) }`, 0, 1},
		{"pointer_lookup_alias_store", `p := new(string); *p = "safe"; m := map[string]*string{"p": p}; *m["p"] = source(); for _, v := range m { sink(*v) }`, 0, 1},
		{"phi_write_then_clear_same_phi", `m := make(map[string]string); if flag() { m = make(map[string]string) }; m["q"] = source(); clear(m); for _, v := range m { sink(v) }`, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cg, pkg := detailedGraphForSource(t, mapRangeBoundaryProgram(tc.body))
			got := CheckDetailed(cg, NewSources(pkg+".source"), NewSinks(pkg+".sink"))
			if len(got) != tc.observed {
				t.Fatalf("known limitation changed: got %d, recorded %d, semantic expectation %d; review and promote this case to the supported suite", len(got), tc.observed, tc.semanticWant)
			}
			t.Logf("known precision limit: observed %d, semantic expectation %d", tc.observed, tc.semanticWant)
		})
	}
}

func TestMapRangeTupleComponents(t *testing.T) {
	for _, tc := range []struct {
		name, literal string
		key, value    bool
	}{
		{"key_only", `map[string]string{source(): "safe"}`, true, false},
		{"value_only", `map[string]string{"safe": source()}`, false, true},
		{"both", `map[string]string{source(): source()}`, true, true},
		{"clean", `map[string]string{"safe": "safe"}`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cg, pkg := detailedGraphForSource(t, mapRangeBoundaryProgram(`m := `+tc.literal+`; for k, v := range m { sink(k); sink(v) }`))
			seen := map[int]bool{}
			for fn := range cg.Nodes {
				if fn == nil || fn.Name() != "main" {
					continue
				}
				for _, block := range fn.Blocks {
					for _, instr := range block.Instrs {
						extract, ok := instr.(*ssa.Extract)
						if !ok {
							continue
						}
						next, ok := extract.Tuple.(*ssa.Next)
						if !ok || next.IsString {
							continue
						}
						seen[extract.Index] = true
						ctx := newTaintContext(NewSources(pkg+".source"), defaultMaxSummaryDepth)
						got, _, _ := checkSSAValueWithContext(nil, ctx, extract, valueSet{})
						want := extract.Index == 1 && tc.key || extract.Index == 2 && tc.value
						if got != want {
							t.Errorf("component %d: tainted=%v, want %v", extract.Index, got, want)
						}
					}
				}
			}
			if len(seen) != 3 {
				t.Fatalf("expected status/key/value extracts, got %v", seen)
			}
		})
	}
}

// Test uninstantiated generic bodies as well as a concrete named map. These
// roots write their own map, so no generic helper-return behavior is assumed.
func TestCheckDetailedGenericMapRange(t *testing.T) {
	for _, constraint := range []string{"~map[string]string", "map[string]string", "M", "map[string]string | M", "maps"} {
		for _, tc := range []struct {
			name, body string
			want       int
		}{
			{"value", `m := make(T); m["q"] = source(); for _, v := range m { sink(v) }`, 1},
			{"key", `m := make(T); m[source()] = "safe"; for k := range m { sink(k) }`, 1},
			{"value_isolation", `m := make(T); m[source()] = "safe"; for _, v := range m { sink(v) }`, 0},
			{"key_isolation", `m := make(T); m["q"] = source(); for k := range m { sink(k) }`, 0},
			{"clear", `m := make(T); m["q"] = source(); clear(m); for _, v := range m { sink(v) }`, 0},
			{"nil", `var m T; _ = source(); for _, v := range m { sink(v) }`, 0},
		} {
			t.Run(constraint+"/"+tc.name, func(t *testing.T) {
				cg, pkg := detailedGraphForSourceRoot(t, "package main\n"+mapRangeBoundaryHelpers+`
type M map[string]string
type maps interface { ~map[string]string }
func handler[T `+constraint+`]() { `+tc.body+` }
func main() {}`, "handler")
				got := CheckDetailed(cg, NewSources(pkg+".source"), NewSinks(pkg+".sink"))
				if len(got) != tc.want {
					t.Fatalf("got %d diagnostics, want %d", len(got), tc.want)
				}
			})
		}
	}
}

func TestCheckDetailedMapRangeEvidence(t *testing.T) {
	const program = `package main
func keySource() string { return "key" }
func valueSource() string { return "value" }
func sink(string) {}
func main() {
	m := map[string]string{keySource(): valueSource()}
	for k, v := range m {
		sink(k)
		sink(v)
	}
}
`
	cg, pkg := detailedGraphForSource(t, program)
	sources, sinks := NewSources(pkg+".keySource", pkg+".valueSource"), NewSinks(pkg+".sink")
	want := CheckDetailed(cg, sources, sinks)
	if len(want) != 2 {
		t.Fatalf("got %d diagnostics, want 2", len(want))
	}
	for i, d := range want {
		sourceName := []string{"keySource", "valueSource"}[i]
		if d.Result.SourceType != pkg+"."+sourceName || d.Result.SourceValue == nil {
			t.Fatalf("diagnostic %d has wrong source: %+v", i, d.Result)
		}
		source, ok := d.Result.SourceValue.(*ssa.Function)
		if !ok || source.Name() != sourceName || source.Prog.Fset.Position(source.Pos()).Line != 2+i {
			t.Fatalf("diagnostic %d has wrong source declaration position: %v", i, d.Result.SourceValue)
		}
		if pos := source.Prog.Fset.Position(d.Result.ReportPos()); pos.Line != 8+i {
			t.Fatalf("diagnostic %d report position = %v, want line %d", i, pos, 8+i)
		}
		assertEvidenceOrder(t, evidenceKinds(d.Evidence), EvidenceSourceMatch, EvidenceSinkMatch)
		assertEvidenceRule(t, d.Evidence, EvidenceSourceMatch, pkg+"."+sourceName)
		assertEvidenceRule(t, d.Evidence, EvidenceSinkMatch, pkg+".sink")
		assertEvidenceContains(t, evidenceKinds(d.Evidence), EvidencePropagationStep)
	}
	for i := 0; i < 20; i++ {
		if got := CheckDetailed(cg, sources, sinks); !reflect.DeepEqual(got, want) {
			t.Fatalf("run %d changed full diagnostics/evidence: got %#v, want %#v", i, got, want)
		}
	}
}
