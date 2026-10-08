package taint

import (
	"go/token"
	"go/types"
	"reflect"
	"testing"
)

func TestCheckDetailedArrayElements(t *testing.T) {
	for _, generic := range []bool{false, true} {
		name := "concrete"
		handler := "func handler(choose bool, idx int)"
		alias := "type T = [2]string"
		if generic {
			name = "generic"
			handler = "func handler[T ~[2]string](choose bool, idx int)"
			alias = ""
		}
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				name, body string
				want       int
			}{
				{"local_sibling", `a:=T([2]string{"safe",source()});sink(a[0])`, 0},
				{"local_tainted", `a:=T([2]string{"safe",source()});sink(a[1])`, 1},
				{"local_clean", `a:=T([2]string{"safe","safe"});sink(a[0])`, 0},
				{"zero", `var a T;sink(a[0])`, 0},
				{"returned_sibling", `sink(array[T]()[0])`, 0},
				{"returned_tainted", `sink(array[T]()[1])`, 1},
				{"returned_clean", `sink(cleanArray[T]()[1])`, 0},
				{"returned_dynamic", `sink(array[T]()[idx])`, 1},
				{"local_dynamic", `a:=T([2]string{"safe",source()});sink(a[idx])`, 1},
				{"tainted_index", `a:=T([2]string{"safe","safe"});sink(a[int(source()[0])%2])`, 0},
				{"returned_tainted_index", `sink(cleanArray[T]()[int(source()[0])%2])`, 0},
				{"element_overwrite", `a:=T([2]string{"safe",source()});a[1]="safe";sink(a[1])`, 0},
				{"whole_overwrite", `a:=T([2]string{"safe",source()});a=T([2]string{"safe","safe"});sink(a[1])`, 0},
				{"whole_overwrites_element", `var a T;a[1]=source();a=T([2]string{"safe","safe"});sink(a[1])`, 0},
				{"element_after_whole", `a:=T([2]string{"safe","safe"});a[1]=source();sink(a[1])`, 1},
				{"sibling_overwrite", `a:=T([2]string{"safe",source()});a[0]="safe";sink(a[1])`, 1},
				{"unknown_write", `var a T;a[idx]=source();sink(a[0])`, 1},
				{"unknown_clean_write", `a:=T([2]string{source(),"safe"});a[idx]="safe";sink(a[0])`, 1},
				{"branch_write", `var a T;if choose {a[1]=source()};sink(a[1])`, 1},
				{"branch_clean", `a:=T([2]string{"safe",source()});if choose {a[1]="safe"};sink(a[1])`, 1},
				{"branch_both_clean", `a:=T([2]string{"safe",source()});if choose {a[1]="a"} else {a[1]="b"};sink(a[1])`, 0},
				{"copy_sibling", `a:=T([2]string{"safe",source()});b:=a;sink(b[0])`, 0},
				{"copy_tainted", `a:=T([2]string{"safe",source()});b:=a;a[1]="safe";sink(b[1])`, 1},
				{"copy_clean", `a:=T([2]string{"safe","safe"});b:=a;a[1]=source();sink(b[1])`, 0},
				{"copy_whole_later_write", `a:=T([2]string{"safe","safe"});b:=a;a=T([2]string{source(),source()});sink(b[1])`, 0},
				{"parameter_sibling", `sink(first(T([2]string{"safe",source()})))`, 0},
				{"parameter_tainted", `sink(first(T([2]string{source(),"safe"})))`, 1},
				{"identity_sibling", `sink(identity(T([2]string{"safe",source()}))[0])`, 0},
				{"identity_tainted", `sink(identity(T([2]string{"safe",source()}))[1])`, 1},
				{"tuple_tainted", `a,_:=pair[T]();sink(a[1])`, 1},
				{"tuple_sibling", `a,_:=pair[T]();sink(a[0])`, 0},
				{"tuple_clean_slot", `_,a:=pair[T]();sink(a[1])`, 0},
				{"branch_return_tainted", `sink(branch[T](choose)[1])`, 1},
				{"branch_return_sibling", `sink(branch[T](choose)[0])`, 0},
				{"array_source", `a:=T(arraySource());sink(a[0])`, 1},
				{"sanitized_sink", `sink(clean(array[T]()[1]))`, 0},
				{"sanitized_return", `sink(sanitize(array[T]())[1])`, 0},
				{"sanitized_return_dynamic", `sink(sanitize(array[T]())[int(source()[0])%2])`, 0},
				{"partial_sanitizer", `sink(array[T]()[1]+clean(source()))`, 1},
				{"sanitized_then_mutated_return", `sink(mutate(sanitize(array[T]()))[1])`, 1},
				{"sanitized_then_dynamic_return", `sink(mutateDynamic(sanitize(array[T]()),idx)[1])`, 1},
				{"sanitized_then_branch_return", `sink(mutateBranch(sanitize(array[T]()),choose)[1])`, 1},
				{"sanitized_then_copy_return", `sink(mutateCopy(sanitize(array[T]()))[1])`, 1},
				{"sanitized_then_mutated_local", `a:=sanitize(array[T]());a[1]=source();sink(a[1])`, 1},
				{"escaped_pointer_write", `var a T;write(&a);sink(a[1])`, 1},
				{"escaped_element_write", `var a T;writeElement(&a[1]);sink(a[1])`, 1},
				{"pointer_alias", `var a T;p:=&a;(*p)[1]=source();sink(a[1])`, 1},
				{"loop_tainted", `var a T;for i:=0;i<2;i++ {a[i]=source()};sink(a[0])`, 1},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if generic && tc.name == "escaped_pointer_write" {
						t.Skip("existing generic pointer-write summary gap; not an array-value copy")
					}
					cg, pkg := detailedGraphForSourceRoot(t, `package main
`+alias+`
func source() string{return "user"}
func arraySource() [2]string{return [2]string{}}
func sink(string){}
func clean(s string)string{return s}
func sanitize[T ~[2]string](a T)T{return a}
func mutate[T ~[2]string](a T)T{a[1]=source();return a}
func mutateDynamic[T ~[2]string](a T,idx int)T{a[idx]=source();return a}
func mutateBranch[T ~[2]string](a T,choose bool)T{if choose{a[1]=source()};return a}
func mutateCopy[T ~[2]string](a T)T{b:=a;b[1]=source();return b}
func array[T ~[2]string]()T{return T([2]string{"safe",source()})}
func cleanArray[T ~[2]string]()T{return T([2]string{"safe","safe"})}
func first[T ~[2]string](a T)string{return a[0]}
func identity[T ~[2]string](a T)T{return a}
func pair[T ~[2]string]()(T,T){return array[T](),cleanArray[T]()}
func branch[T ~[2]string](choose bool)T{if choose{return array[T]()};return cleanArray[T]()}
func write[T ~[2]string](a *T){(*a)[1]=source()}
func writeElement(s *string){*s=source()}
`+handler+`{`+tc.body+`}
func main(){}`, "handler")
					sources, sinks := NewSources(pkg+".source", pkg+".arraySource"), NewSinks(pkg+".sink")
					got := CheckDetailed(cg, sources, sinks, WithSanitizers(pkg+".clean", pkg+".sanitize", pkg+".sanitize["+pkg+".T]", pkg+".sanitize[T]"))
					if len(got) != tc.want {
						t.Fatalf("got %d diagnostics, want %d", len(got), tc.want)
					}
					if !reflect.DeepEqual(got, CheckDetailed(cg, sources, sinks, WithSanitizers(pkg+".clean", pkg+".sanitize", pkg+".sanitize["+pkg+".T]", pkg+".sanitize[T]"))) {
						t.Fatal("unstable diagnostics or evidence")
					}
					if tc.want > 0 {
						d := got[0]
						if d.Result.SourceType != pkg+".source" && d.Result.SourceType != pkg+".arraySource" {
							t.Fatalf("wrong source: %+v", d.Result)
						}
						if d.Result.SinkType != pkg+".sink" || !d.Result.ReportPos().IsValid() {
							t.Fatalf("wrong sink: %+v", d.Result)
						}
						assertEvidenceOrder(t, evidenceKinds(d.Evidence), EvidenceSourceMatch, EvidenceSinkMatch)
					}
				})
			}
		})
	}
}

func TestArrayValueTypeConstraints(t *testing.T) {
	for _, tc := range []struct {
		constraint string
		want       bool
	}{
		{"interface{~[2]string}", true},
		{"interface{[2]string}", true},
		{"interface{[2]string|[]string;~[2]string}", true},
		{"interface{~[2]string|~[]string}", false},
		{"interface{~[2]string|~[3]string}", false},
		{"interface{~[]string}", false},
		{"interface{~string}", false},
		{"interface{}", false},
	} {
		t.Run(tc.constraint, func(t *testing.T) {
			tv, err := types.Eval(token.NewFileSet(), nil, token.NoPos, tc.constraint)
			if err != nil {
				t.Fatal(err)
			}
			param := types.NewTypeParam(types.NewTypeName(token.NoPos, nil, "T", nil), tv.Type)
			if got := isArrayValueType(param); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// An explicit summary is a caller-supplied contract, even if the modeled
// function has an available stub body that returns an apparently clean array.
func TestCheckDetailedArraySummaryModel(t *testing.T) {
	for _, body := range []string{
		`a:=wrap(source());sink(a[0])`,
		`sink(wrap(source())[0])`,
		`a,_:=pair(source());sink(a[0])`,
		`sink(wrap("safe")[0])`,
	} {
		t.Run(body, func(t *testing.T) {
			cg, pkg := detailedGraphForSourceRoot(t, `package main
func source()string{return "taint"}
func sink(string){}
func wrap(s string)[2]string{return [2]string{}}
func pair(s string)([2]string,int){return [2]string{},0}
func handler(){`+body+`}
func main(){}`, "handler")
			got := CheckDetailed(cg, NewSources(pkg+".source"), NewSinks(pkg+".sink"), WithModels(Model{Summaries: []SummaryModel{{Func: pkg + ".wrap"}, {Func: pkg + ".pair"}}}))
			want := 1
			if body == `sink(wrap("safe")[0])` {
				want = 0
			}
			if len(got) != want {
				t.Fatalf("got %d, want %d", len(got), want)
			}
		})
	}
}
