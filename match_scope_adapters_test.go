package taint

import (
	"github.com/picatz/taint/callgraphutil"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func independentScopeProgram(t *testing.T) (*ssa.Package, *ssa.Package) {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.com/scope\ngo 1.26.0\n",
		"api/api.go": `package api
 type Input struct { Text, Safe string }
 type Alias = Input
 type Box struct { Text, Safe string }
 type DB struct{}
 func (*DB) Sink(string){}
 func Source() string { return "input" }
 func SinkReturn(s string) string { return s }
 type Printer struct{}
 func (*Printer) Sink(s string) {}
 func (*Printer) Source() string { return "input" }
 type Print interface { Sink(string) }
 func NewInput() *Input { return new(Input) }

 func ArraySource() [2]string { return [2]string{} }
 func BoxSource() Box { return Box{} }
 func Sink(string) {}
 func Clean(s string) string { return s }
 func Model(s string) string { return "safe" }
 func (r *Input) Value() string { return r.Text }
 `,
		"helper/helper.go": `package helper
 import "example.com/scope/api"
 func Identity(s string) string { return s }
 func BoundSink(s string) { p:=new(api.Printer); f:=p.Sink; f(s) }
 func ExprSink(s string) { p:=new(api.Printer); f:=(*api.Printer).Sink; f(p,s) }
 func BoundOwn() string { p:=new(api.Printer); f:=p.Source; return f() }
 func ExprOwn() string { p:=new(api.Printer); f:=(*api.Printer).Source; return f(p) }
 func InvokeSource(f func()string) string { return f() }
 func InvokeSink(f func(string),s string) { f(s) }
 func InvokeClosureSink(f func(string),s string) { f(s) }
 func MakeSource() func()string { p:=new(api.Printer); return p.Source }
 func MakeSink() func(string) { p:=new(api.Printer); return p.Sink }
 func OwnTypeTransit() string { r:=new(api.Input); return Type(r) }
 func GenericOwn[T any]() string { return api.Source() }
 type Embedded struct { *api.Printer }
 func PromotedOwn() string { p:=&Embedded{new(api.Printer)}; f:=(*Embedded).Source; return f(p) }
 func PromotedSink(s string) { p:=&Embedded{new(api.Printer)}; f:=(*Embedded).Sink; f(p,s) }

 func Constant(s string) string { return "safe" }
 func Own() string { return api.Source() }
 func OwnBox() api.Box { return api.BoxSource() }
 func OwnArray() [2]string { return api.ArraySource() }
 func Sink(s string) { api.Sink(s) }
 func Box(s string) api.Box { return api.Box{Text:s,Safe:"safe"} }
 func Array(s string) [2]string { return [2]string{"safe",s} }
 func Clean(s string) string { return api.Clean(s) }
 func Model(s string) string { return api.Model(s) }
 func Type(r *api.Input) string { return r.Text }
 func OwnType() string { r:=new(api.Input); return r.Text }
 func Receiver(r *api.Input) string { return r.Value() }
 func Generic[T ~string](s T) T { return s }
 func Closure(s string) string { f:=func()string{return s}; return f() }
 func Transit(s string, next func(string)) { next(s) }
 `,
		"caller/caller.go": `package caller
 import ("example.com/scope/api";"example.com/scope/helper")
 var initialized = api.SinkReturn(api.Source())
 func Direct() { api.Sink(api.Source()) }
 func SharedClosureSink() { f:=func(s string){api.Sink(s)}; f(api.Source()); helper.InvokeClosureSink(f,api.Source()) }

 type Embedded struct { *api.Printer }
 func OutsideBoundSink() { helper.BoundSink(api.Source()) }
 func OutsideExprSink() { helper.ExprSink(api.Source()) }
 func OutsideBoundSource() { api.Sink(helper.BoundOwn()) }
 func OutsideExprSource() { api.Sink(helper.ExprOwn()) }
 func OutsidePromotedSource() { api.Sink(helper.PromotedOwn()) }
 func OutsidePromotedSink() { helper.PromotedSink(api.Source()) }
 func OutsideTypeTransit() { api.Sink(helper.OwnTypeTransit()) }
 func SharedSource() { p:=new(api.Printer); f:=p.Source; api.Sink(f()); api.Sink(helper.BoundOwn()) }
 func SharedSink() { p:=new(api.Printer); f:=p.Sink; f(api.Source()); helper.BoundSink(api.Source()) }
 func PromotedSource() { p:=&Embedded{new(api.Printer)}; f:=(*Embedded).Source; api.Sink(f(p)) }
 func PromotedSink() { p:=&Embedded{new(api.Printer)}; f:=(*Embedded).Sink; f(p,api.Source()) }
 func GenericOwn[T any]() { api.Sink(api.Source()) }
 func GenericOwner() { GenericOwn[int]() }
 func GenericOutside() { api.Sink(helper.GenericOwn[int]()) }
 func GoSink() { go api.Sink(api.Source()) }
 func DeferSink() { defer api.Sink(api.Source()) }
 func CallbackSource() { p:=new(api.Printer); api.Sink(helper.InvokeSource(p.Source)) }
 func CallbackSink() { p:=new(api.Printer); helper.InvokeSink(p.Sink,api.Source()) }
 func ForeignBoundSource() { f:=helper.MakeSource(); api.Sink(f()) }
 func ForeignBoundSink() { f:=helper.MakeSink(); f(api.Source()) }

 func MethodSink() { p:=new(api.Printer); p.Sink(api.Source()) }
 func BoundSink() { p:=new(api.Printer); f:=p.Sink; f(api.Source()) }
 func ExprSink() { p:=new(api.Printer); f:=(*api.Printer).Sink; f(p,api.Source()) }
 func InterfaceSink() { var p api.Print = new(api.Printer); p.Sink(api.Source()) }
 func BoundSource() { p:=new(api.Printer); f:=p.Source; api.Sink(f()) }
 func ExprSource() { p:=new(api.Printer); f:=(*api.Printer).Source; api.Sink(f(p)) }
 func AllocTypeThrough() { r:=new(api.Input); api.Sink(helper.Type(r)) }
 func CallTypeThrough() { r:=api.NewInput(); api.Sink(helper.Type(r)) }

 func Bound() { db:=new(api.DB); f:=db.Sink; f(api.Source()) }
 func MethodExpression() { db:=new(api.DB); (*api.DB).Sink(db,api.Source()) }
 func Identity() { api.Sink(helper.Identity(api.Source())) }
 func Constant() { api.Sink(helper.Constant(api.Source())) }
 func Own() { api.Sink(helper.Own()) }
 func HelperSink() { helper.Sink(api.Source()) }
 func Box() { api.Sink(helper.Box(api.Source()).Text) }
 func BoxSibling() { api.Sink(helper.Box(api.Source()).Safe) }
 func OwnBox() { api.Sink(helper.OwnBox().Text) }
 func Array() { api.Sink(helper.Array(api.Source())[1]) }
 func ArraySibling() { api.Sink(helper.Array(api.Source())[0]) }
 func OwnArray() { api.Sink(helper.OwnArray()[1]) }
 func Clean() { api.Sink(helper.Clean(api.Source())) }
 func Model() { api.Sink(helper.Model(api.Source())) }
 func Type(r *api.Input) { api.Sink(r.Text) }
 func TypeAlias(r *api.Alias) { api.Sink(r.Text) }
 func FieldSibling(r *api.Input) { api.Sink(r.Safe) }
 func FieldThrough(r *api.Input) { api.Sink(helper.Identity(r.Text)) }
 func TypeThrough(r *api.Input) { api.Sink(helper.Type(r)) }
 func OwnType() { api.Sink(helper.OwnType()) }
 func Receiver(r *api.Input) { api.Sink(r.Value()) }
 func ReceiverThrough(r *api.Input) { api.Sink(helper.Receiver(r)) }
 func Generic() { api.Sink(helper.Generic(api.Source())) }
 func Closure() { f:=func(){api.Sink(api.Source())}; f() }
 func ClosureThrough() { api.Sink(helper.Closure(api.Source())) }
 func Transit() { helper.Transit(api.Source(),func(s string){api.Sink(s)}) }
 `,
	}
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOWORK", "off")
	pkgs, err := packages.Load(&packages.Config{Dir: dir, Mode: packages.LoadAllSyntax}, "./caller", "./helper")
	if err != nil {
		t.Fatal(err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("package load failed")
	}
	prog, built := ssautil.Packages(pkgs, ssa.InstantiateGenerics)
	prog.Build()
	var caller, helper *ssa.Package
	for _, p := range built {
		switch p.Pkg.Name() {
		case "caller":
			caller = p
		case "helper":
			helper = p
		}
	}
	return caller, helper
}

func TestIndependentReview(t *testing.T) {
	caller, helper := independentScopeProgram(t)
	const api = "example.com/scope/api"
	for _, tc := range []struct {
		name, source, sink string
		expected           int
	}{
		{"init", api + ".Source", api + ".SinkReturn", 1},
		{"MethodSink", api + ".Source", "(*" + api + ".Printer).Sink", 1},
		{"BoundSink", api + ".Source", "(*" + api + ".Printer).Sink", 1},
		{"ExprSink", api + ".Source", "(*" + api + ".Printer).Sink", 1},
		{"BoundSource", "(*" + api + ".Printer).Source", api + ".Sink", 1},
		{"ExprSource", "(*" + api + ".Printer).Source", api + ".Sink", 1},
		{"AllocTypeThrough", "*" + api + ".Input", api + ".Sink", 1},
		{"CallTypeThrough", "*" + api + ".Input", api + ".Sink", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fn := caller.Func(tc.name)
			cg, err := callgraphutil.NewGraph(fn)
			if err != nil {
				t.Fatal(err)
			}
			legacy := CheckDetailed(cg, NewSources(tc.source), NewSinks(tc.sink))
			got := CheckDetailed(cg, NewSources(tc.source), NewSinks(tc.sink), WithMatchPackages(caller.Pkg))
			all := CheckDetailed(cg, NewSources(tc.source), NewSinks(tc.sink), WithMatchPackages(caller.Pkg, helper.Pkg))
			t.Logf("legacy=%d scoped=%d all=%d synthetic=%q", len(legacy), len(got), len(all), fn.Synthetic)
			if len(got) != tc.expected {
				t.Errorf("expected %d got %d", tc.expected, len(got))
			}
		})
	}
}

func TestIndependentScopeLaundering(t *testing.T) {
	caller, helper := independentScopeProgram(t)
	const api = "example.com/scope/api"
	for _, tc := range []struct {
		name             string
		expected, legacy int
	}{
		{"OutsideBoundSink", 0, 1}, {"OutsideExprSink", 0, 1},
		{"OutsideBoundSource", 0, 1}, {"OutsideExprSource", 0, 1},
		{"OutsidePromotedSource", 0, 1}, {"OutsidePromotedSink", 0, 1},
		{"OutsideTypeTransit", 0, 1}, {"SharedSource", 1, 2}, {"SharedSink", 1, 2},
		{"PromotedSource", 1, 1}, {"PromotedSink", 1, 1},
		{"GenericOwner", 1, 1}, {"GenericOutside", 0, 1},
		{"GoSink", 1, 1}, {"DeferSink", 1, 1}, {"SharedClosureSink", 1, 1},
		{"CallbackSink", 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cg, err := callgraphutil.NewGraph(caller.Func(tc.name))
			if err != nil {
				t.Fatal(err)
			}
			src := NewSources(api+".Source", "(*"+api+".Printer).Source")
			if tc.name == "OutsideTypeTransit" {
				src["*"+api+".Input"] = struct{}{}
			}
			sinks := NewSinks(api+".Sink", "(*"+api+".Printer).Sink")
			legacy := CheckDetailed(cg, src, sinks)
			got := CheckDetailed(cg, src, sinks, WithMatchPackages(caller.Pkg))
			all := CheckDetailed(cg, src, sinks, WithMatchPackages(caller.Pkg, helper.Pkg))
			t.Logf("legacy=%d scoped=%d all=%d", len(legacy), len(got), len(all))
			if tc.legacy >= 0 && len(legacy) != tc.legacy {
				t.Errorf("legacy expected %d got %d", tc.legacy, len(legacy))
			}
			if tc.legacy >= 0 && len(got) != tc.expected {
				t.Errorf("expected %d got %d", tc.expected, len(got))
			}
			if !reflect.DeepEqual(legacy, all) {
				t.Errorf("all differs from legacy")
			}
		})
	}
}
