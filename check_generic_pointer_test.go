package taint

import (
	"go/token"
	"go/types"
	"golang.org/x/tools/go/ssa"
	"reflect"
	"testing"
)

func TestCheckDetailedGenericPointerWrite(t *testing.T) {
	for _, generic := range []bool{false, true} {
		name, alias, handler := "concrete", "type T = [2]string", "func handler(choose bool,idx int)"
		if generic {
			name, alias, handler = "generic", "", "func handler[T ~[2]string](choose bool,idx int)"
		}
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				name, body string
				want       int
			}{
				{"selected", `var a T; write(&a,source());sink(a[1])`, 1},
				{"sibling", `var a T; write(&a,source());sink(a[0])`, 0},
				{"clean", `var a T; write(&a,"safe");sink(a[1])`, 0},
				{"unrelated_source", `var a T;_ = source();write(&a,"safe");sink(a[1])`, 0},
				{"alias", `var a T;p:=&a;write(p,source());sink(a[1])`, 1},
				{"other_array", `var a,b T;write(&a,source());sink(b[1])`, 0},
				{"overwrite", `var a T;write(&a,source());write(&a,"safe");sink(a[1])`, 0},
				{"local_overwrite", `var a T;write(&a,source());a[1]="safe";sink(a[1])`, 0},
				{"branch", `var a T;if choose{write(&a,source())};sink(a[1])`, 1},
				{"conditional_clean", `var a T;write(&a,source());if choose{write(&a,"safe")};sink(a[1])`, 1},
				{"callee_branch", `var a T;conditional(&a,source(),choose);sink(a[1])`, 1},
				{"callee_branch_clean", `var a T;write(&a,source());conditional(&a,"safe",choose);sink(a[1])`, 1},
				{"dynamic_write", `var a T;dynamic(&a,source(),idx);sink(a[1])`, 1},
				{"dynamic_clean", `var a T;write(&a,source());dynamic(&a,"safe",idx);sink(a[1])`, 1},
				{"dynamic_read", `var a T;write(&a,source());sink(a[idx])`, 1},
				{"tainted_index", `var a T;dynamic(&a,"safe",int(source()[0])%2);sink(a[1])`, 0},
				{"sanitized_value", `var a T;write(&a,clean(source()));sink(a[1])`, 0},
				{"sanitized_sink", `var a T;write(&a,source());sink(clean(a[1]))`, 0},
				{"modeled_value", `var a T;write(&a,modeled(source()));sink(a[1])`, 1},
				{"modeled_clean", `var a T;write(&a,modeled("safe"));sink(a[1])`, 0},
			} {
				t.Run(tc.name, func(t *testing.T) {
					cg, pkg := detailedGraphForSourceRoot(t, `package main
`+alias+`
func source()string{return "user"}
func sink(string){}
func clean(s string)string{return s}
func modeled(s string)string{return "safe"}
func write[T ~[2]string](a *T,s string){(*a)[1]=s}
func conditional[T ~[2]string](a *T,s string,choose bool){if choose{(*a)[1]=s}}
func dynamic[T ~[2]string](a *T,s string,idx int){(*a)[idx]=s}
`+handler+`{`+tc.body+`}
func main(){}`, "handler")
					opts := []Option{WithSanitizers(pkg + ".clean"), WithModels(Model{Summaries: []SummaryModel{{Func: pkg + ".modeled"}}})}
					got := CheckDetailed(cg, NewSources(pkg+".source"), NewSinks(pkg+".sink"), opts...)
					if len(got) != tc.want {
						t.Fatalf("got %d diagnostics, want %d", len(got), tc.want)
					}
					if !reflect.DeepEqual(got, CheckDetailed(cg, NewSources(pkg+".source"), NewSinks(pkg+".sink"), opts...)) {
						t.Fatal("unstable diagnostics")
					}
					if tc.want > 0 {
						d := got[0]
						if d.Result.SourceType != pkg+".source" || d.Result.SinkType != pkg+".sink" || !d.Result.ReportPos().IsValid() {
							t.Fatalf("wrong attribution: %+v", d.Result)
						}
						assertEvidenceOrder(t, evidenceKinds(d.Evidence), EvidenceSourceMatch, EvidenceSinkMatch)
					}
				})
			}
		})
	}
}

func TestPointerSummaryCalleeRejectsNonForwarding(t *testing.T) {
	cg, _ := detailedGraphForSourceRoot(t, `package main
func write[T ~[2]string](a *T,b *T){(*a)[1]="safe"}
func handler[T ~[2]string](){var a,b T;write(&a,&b)}
func main(){}`, "handler")
	var wrapper *ssa.Function
	for fn := range cg.Nodes {
		if fn != nil && fn.Name() == "handler" {
			for _, block := range fn.Blocks {
				for _, instr := range block.Instrs {
					if call, ok := instr.(*ssa.Call); ok {
						wrapper = call.Call.StaticCallee()
					}
				}
			}
		}
	}
	if wrapper == nil || pointerSummaryCallee(wrapper) != wrapper.Origin() {
		t.Fatal("did not resolve generated wrapper")
	}
	if got := pointerSummaryCallee(wrapper.Origin()); got != wrapper.Origin() {
		t.Fatal("changed original function")
	}
	if pointerSummaryCallee(nil) != nil {
		t.Fatal("changed nil function")
	}
	for _, name := range []string{"reordered", "dropped", "extra_call", "store", "results"} {
		t.Run(name, func(t *testing.T) {
			fn := *wrapper
			block := *wrapper.Blocks[0]
			fn.Blocks = []*ssa.BasicBlock{&block}
			block.Instrs = append([]ssa.Instruction(nil), block.Instrs...)
			for i, instr := range block.Instrs {
				if original, ok := instr.(*ssa.Call); ok {
					call := *original
					call.Call.Args = append([]ssa.Value(nil), original.Call.Args...)
					block.Instrs[i] = &call
					switch name {
					case "reordered":
						call.Call.Args[0], call.Call.Args[1] = call.Call.Args[1], call.Call.Args[0]
					case "dropped":
						call.Call.Args = call.Call.Args[:1]
					case "extra_call":
						block.Instrs = append(block.Instrs, &call)
					case "store":
						block.Instrs = append(block.Instrs, &ssa.Store{})
					case "results":
						fn.Signature = types.NewSignatureType(nil, nil, nil, fn.Signature.Params(), types.NewTuple(types.NewVar(token.NoPos, nil, "", types.Typ[types.Int])), false)
					}
					break
				}
			}
			if pointerSummaryCallee(&fn) != &fn {
				t.Fatal("accepted a non-forwarding wrapper")
			}
		})
	}
}
