//go:build go1.27

package taint

import (
	"strings"
	"testing"
)

// Exercise language features in the analyzed program, not just compilation of
// the analyzer itself. The fixture's build constraint enables Go 1.27 syntax
// while the shared loader continues to cover older language versions elsewhere.
func TestCheckDetailedGo127(t *testing.T) {
	tests := []struct {
		name string
		decl string
		body string
	}{
		{
			name: "generic method",
			decl: "type wrapper struct{}; func (wrapper) Wrap[T ~string](v T) string { return string(v) }",
			body: "sink(wrapper{}.Wrap[string](INPUT))",
		},
		{
			name: "inferred generic method",
			decl: "type wrapper struct{}; func (wrapper) Wrap[T ~string](v T) string { return string(v) }",
			body: "sink(wrapper{}.Wrap(INPUT))",
		},
		{
			name: "bound generic method",
			decl: "type wrapper struct{}; func (wrapper) Wrap[T ~string](v T) string { return string(v) }",
			body: "f := wrapper{}.Wrap[string]; sink(f(INPUT))",
		},
		{
			name: "promoted field literal",
			decl: "type inner struct{ Value string }; type outer struct{ inner }",
			body: "v := outer{Value: INPUT}; sink(v.Value)",
		},
		{
			name: "inferred function assignment",
			decl: "func wrap[T ~string](v T) string { return string(v) }",
			body: "var f func(string) string; f = wrap; sink(f(INPUT))",
		},
	}
	for _, tt := range tests {
		for _, tainted := range []bool{true, false} {
			label, input, want := "tainted", "source()", 1
			if !tainted {
				label, input, want = "clean", `"constant"`, 0
			}
			t.Run(tt.name+"/"+label, func(t *testing.T) {
				src := "//go:build go1.27\n\npackage main\n" +
					"func source() string { return \"user\" }\n" +
					"func sink(string) {}\n" + tt.decl + "\n" +
					"func main() { " + strings.ReplaceAll(tt.body, "INPUT", input) + " }\n"
				cg, pkg := detailedGraphForSource(t, src)
				diagnostics := CheckDetailed(cg, NewSources(pkg+".source"), NewSinks(pkg+".sink"))
				if len(diagnostics) != want {
					t.Fatalf("got %d diagnostics, want %d", len(diagnostics), want)
				}
			})
		}
	}
}
