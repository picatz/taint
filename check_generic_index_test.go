package taint

import (
	"go/token"
	"go/types"
	"reflect"
	"testing"
)

// Analyze the generic body itself, without a concrete instantiation. Library
// entry points may retain type parameters even with InstantiateGenerics enabled.
func TestCheckDetailedGenericStringIndex(t *testing.T) {
	for _, tc := range []struct {
		name, constraint, body string
		want                   int
	}{
		{"underlying", "~string", `sink(string(T(source())[0]))`, 1},
		{"exact", "string", `sink(string(T(source())[0]))`, 1},
		{"named", "text", `sink(string(T(source())[0]))`, 1},
		{"union", "string | text", `sink(string(T(source())[0]))`, 1},
		{"embedded", "textual", `sink(string(T(source())[0]))`, 1},
		{"intersection", "interface { string | []byte; ~string }", `sink(string(T(source())[0]))`, 1},
		{"helper", "~string", `sink(first(T(source())))`, 1},
		{"clean", "~string", `sink(string(T("safe")[0]))`, 0},
		{"unrelated_source", "~string", `_ = source(); sink(string(T("safe")[0]))`, 0},
		{"tainted_index", "~string", `sink(string(T("safe")[int(source()[0]) % 4]))`, 0},
		{"sanitized", "~string", `sink(clean(string(T(source())[0])))`, 0},
		{"overwritten", "~string", `s := T(source()); s = T("safe"); sink(string(s[0]))`, 0},
		{"array_sibling", "~[2]string", `sink(array[T]()[0])`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cg, pkg := detailedGraphForSourceRoot(t, `package main
 type text string
 type textual interface { ~string }
 func source() string { return "user" }
 func sink(string) {}
 func clean(s string) string { return s }
 func array[T ~[2]string]() T { return T([2]string{"safe", source()}) }
 func first[T ~string](s T) string { return string(s[0]) }
 func handler[T `+tc.constraint+`]() { `+tc.body+` }
 func main() {}`, "handler")
			sources, sinks := NewSources(pkg+".source"), NewSinks(pkg+".sink")
			got := CheckDetailed(cg, sources, sinks, WithSanitizers(pkg+".clean"))
			if len(got) != tc.want {
				t.Fatalf("got %d diagnostics, want %d", len(got), tc.want)
			}
			if !reflect.DeepEqual(got, CheckDetailed(cg, sources, sinks, WithSanitizers(pkg+".clean"))) {
				t.Fatal("unstable diagnostics or evidence")
			}
			if tc.want == 0 {
				return
			}
			d := got[0]
			if d.Result.SourceType != pkg+".source" || d.Result.SourceValue == nil || d.Result.SourceValue.String() != pkg+".source" {
				t.Fatalf("wrong source attribution: %+v", d.Result)
			}
			if d.Result.SinkType != pkg+".sink" || !d.Result.ReportPos().IsValid() {
				t.Fatalf("wrong sink attribution: %+v", d.Result)
			}
			assertEvidenceOrder(t, evidenceKinds(d.Evidence), EvidenceSourceMatch, EvidenceSinkMatch)
			assertEvidenceRule(t, d.Evidence, EvidenceSourceMatch, pkg+".source")
			assertEvidenceRule(t, d.Evidence, EvidenceSinkMatch, pkg+".sink")
		})
	}
}

// Mixed string/slice unions are valid indexing operands, but a string-only
// propagation rule must not be used for their element-sensitive alternatives.
func TestStringContentTypeConstraints(t *testing.T) {
	for _, tc := range []struct {
		constraint string
		want       bool
	}{
		{"interface { ~string }", true},
		{"interface { string }", true},
		{"interface { ~string; Len() int }", true},
		{"interface { string | []byte; ~string }", true},
		{"interface { ~string | ~[]byte }", false},
		{"interface { ~[]byte }", false},
		{"interface { ~[2]string }", false},
		{"interface { ~int }", false},
		{"interface {}", false},
	} {
		t.Run(tc.constraint, func(t *testing.T) {
			tv, err := types.Eval(token.NewFileSet(), nil, token.NoPos, tc.constraint)
			if err != nil {
				t.Fatal(err)
			}
			param := types.NewTypeParam(types.NewTypeName(token.NoPos, nil, "T", nil), tv.Type)
			if got := isStringContentType(param); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
