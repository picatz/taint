package taint

import (
	"github.com/picatz/taint/callgraphutil"
	"go/types"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func scopeProgram(t *testing.T) (*ssa.Package, *ssa.Package) {
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
 func (*DB) Source() string { return "input" }
 type Print interface { Sink(string) }
 func NewInput() *Input { return new(Input) }
 func SinkReturn(s string) string { return s }
 func Source() string { return "input" }
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
 func Constant(s string) string { return "safe" }
 func Own() string { return api.Source() }
 func OwnGeneric[T ~string]() T { return T(api.Source()) }
 func OwnClosure() string { f:=func()string{return api.Source()}; return f() }
 func OwnBound() string { db:=new(api.DB); f:=db.Source; return f() }
 func OwnExpr() string { db:=new(api.DB); return (*api.DB).Source(db) }
 func BoundSink(s string) { db:=new(api.DB); f:=db.Sink; f(s) }
 func ExprSink(s string) { db:=new(api.DB); (*api.DB).Sink(db,s) }
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
 var initialized=api.SinkReturn(api.Source())
 func Direct() { api.Sink(api.Source()) }
 func SharedSources() { BoundSource(); OwnBound() }
 func SharedSinks() { Bound(); HelperBoundSink() }
 func OwnGeneric() { api.Sink(helper.OwnGeneric[string]()) }
 func OwnClosure() { api.Sink(helper.OwnClosure()) }
 func GenericBody[T ~string]() { api.Sink(api.Source()) }
 func SelectedGeneric() { GenericBody[string]() }
 func BoundSource() { db:=new(api.DB); f:=db.Source; api.Sink(f()) }
 func ExprSource() { db:=new(api.DB); api.Sink((*api.DB).Source(db)) }
 func InterfaceSink() { var p api.Print=new(api.DB); p.Sink(api.Source()) }
 func OwnBound() { api.Sink(helper.OwnBound()) }
 func OwnExpr() { api.Sink(helper.OwnExpr()) }
 func HelperBoundSink() { helper.BoundSink(api.Source()) }
 func HelperExprSink() { helper.ExprSink(api.Source()) }
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

func TestMatchPackageOccurrences(t *testing.T) {
	caller, helper := scopeProgram(t)
	const api = "example.com/scope/api"
	for _, tc := range []struct {
		name           string
		scoped, legacy int
		typ            bool
	}{
		{"SharedSources", 1, 2, false},
		{"SharedSinks", 1, 2, false},
		{"OwnGeneric", 0, 1, false},
		{"OwnClosure", 0, 1, false},
		{"SelectedGeneric", 1, 1, false},
		{"init", 1, 1, false},
		{"BoundSource", 1, 1, false},
		{"ExprSource", 1, 1, false},
		{"OwnBound", 0, 1, false},
		{"OwnExpr", 0, 1, false},
		{"HelperBoundSink", 0, 1, false},
		{"HelperExprSink", 0, 1, false},
		{"AllocTypeThrough", 1, 1, true},
		{"CallTypeThrough", 1, 1, true},
		{"Bound", 1, 1, false},
		{"MethodExpression", 1, 1, false},
		{"Direct", 1, 1, false},
		{"Identity", 1, 1, false},
		{"Constant", 0, 0, false},
		{"Own", 0, 1, false},
		{"HelperSink", 0, 1, false}, // Legacy whole-struct return propagation also taints the safe sibling.
		// Scope must preserve this known precision limitation, not hide it.
		{"Box", 1, 1, false},
		{"BoxSibling", 1, 1, false},
		{"OwnBox", 0, 1, false},
		{"Array", 1, 1, false},
		{"ArraySibling", 0, 0, false},
		{"OwnArray", 0, 1, false},
		{"Clean", 0, 0, false},
		{"Model", 1, 1, false},
		{"Type", 1, 1, true},
		{"TypeAlias", 1, 1, true},
		{"TypeThrough", 1, 1, true},
		{"OwnType", 0, 1, true},
		{"Receiver", 1, 1, true},
		{"ReceiverThrough", 1, 1, true},
		{"Generic", 1, 1, false},
		{"Closure", 1, 1, false},
		{"ClosureThrough", 1, 1, false},
		{"Transit", 1, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cg, err := callgraphutil.NewGraph(caller.Func(tc.name))
			if err != nil {
				t.Fatal(err)
			}
			src := NewSources(api+".Source", api+".ArraySource", api+".BoxSource", "(*"+api+".DB).Source")
			if tc.typ {
				src["*"+api+".Input"] = struct{}{}
			}
			opts := []Option{WithModels(Model{Sanitizers: []SanitizerModel{{Func: api + ".Clean"}}, Summaries: []SummaryModel{{Func: api + ".Model"}}})}
			legacy := CheckDetailed(cg, src, NewSinks(api+".Sink", "(*"+api+".DB).Sink", api+".SinkReturn"), opts...)
			if len(legacy) != tc.legacy {
				t.Fatalf("legacy got %d want %d", len(legacy), tc.legacy)
			}
			got := CheckDetailed(cg, src, NewSinks(api+".Sink", "(*"+api+".DB).Sink", api+".SinkReturn"), append(opts, WithMatchPackages(caller.Pkg))...)
			if len(got) != tc.scoped {
				t.Errorf("scoped got %d want %d", len(got), tc.scoped)
				for _, d := range legacy {
					for _, e := range d.Result.Path {
						if e.Site != nil {
							t.Logf("site owner=%s synthetic=%q target=%s targetSynthetic=%q", e.Site.Parent(), e.Site.Parent().Synthetic, e.Callee.Func, e.Callee.Func.Synthetic)
						}
					}
				}
			}
			if empty := CheckDetailed(cg, src, NewSinks(api+".Sink", "(*"+api+".DB).Sink", api+".SinkReturn"), append(opts, WithMatchPackages())...); len(empty) != 0 {
				t.Error("empty scope matched")
			}
			all := CheckDetailed(cg, src, NewSinks(api+".Sink", "(*"+api+".DB).Sink", api+".SinkReturn"), append(opts, WithMatchPackages(caller.Pkg, helper.Pkg))...)
			if !reflect.DeepEqual(legacy, all) {
				t.Errorf("all source packages differ: %d/%d", len(legacy), len(all))
			}
			if !reflect.DeepEqual(legacy, CheckDetailed(cg, src, NewSinks(api+".Sink", "(*"+api+".DB).Sink", api+".SinkReturn"), opts...)) {
				t.Error("scoped call mutated default")
			}
		})
	}
}

func TestMatchPackageFieldSources(t *testing.T) {
	caller, _ := scopeProgram(t)
	const api = "example.com/scope/api"
	for _, name := range []string{"Type", "TypeAlias", "OwnType", "FieldSibling", "FieldThrough"} {
		t.Run(name, func(t *testing.T) {
			cg, err := callgraphutil.NewGraph(caller.Func(name))
			if err != nil {
				t.Fatal(err)
			}
			model := WithModels(Model{Sources: []SourceModel{{Type: "*" + api + ".Input", Field: "Text"}}, Sinks: []SinkModel{{Method: api + ".Sink"}}})
			legacy := CheckDetailed(cg, nil, nil, model)
			legacyWant := 1
			if name == "FieldSibling" {
				legacyWant = 0
			}
			if len(legacy) != legacyWant {
				t.Fatalf("legacy got %d want %d", len(legacy), legacyWant)
			}
			want := 1
			if name == "OwnType" || name == "FieldSibling" {
				want = 0
			}
			if got := CheckDetailed(cg, nil, nil, model, WithMatchPackages(caller.Pkg)); len(got) != want {
				t.Fatalf("scoped got %d want %d", len(got), want)
			}
		})
	}
}

func TestMatchPackageIdentityAndEmpty(t *testing.T) {
	caller, _ := scopeProgram(t)
	cg, err := callgraphutil.NewGraph(caller.Func("Direct"))
	if err != nil {
		t.Fatal(err)
	}
	src, sink := NewSources("example.com/scope/api.Source"), NewSinks("example.com/scope/api.Sink")
	for _, opt := range []Option{WithMatchPackages(), WithMatchPackages(nil), WithMatchPackages(types.NewPackage(caller.Pkg.Path(), caller.Pkg.Name()))} {
		if len(CheckDetailed(cg, src, sink, opt)) != 0 {
			t.Fatal("empty or different package identity matched")
		}
	}
	packages := []*types.Package{caller.Pkg}
	opt := WithMatchPackages(packages...)
	packages[0] = nil
	if len(CheckDetailed(cg, src, sink, opt)) != 1 {
		t.Fatal("option retained caller slice")
	}
	if len(CheckDetailed(cg, src, sink, opt, WithMatchPackages())) != 0 {
		t.Fatal("last empty option ignored")
	}
	if occurrenceInPackages(nil, map[*types.Package]struct{}{caller.Pkg: {}}) {
		t.Fatal("unknown owner matched")
	}
	synthetic := caller.Prog.NewFunction("synthetic", nil, "unknown")
	if occurrenceInPackages(synthetic, map[*types.Package]struct{}{caller.Pkg: {}}) {
		t.Fatal("synthetic owner matched")
	}
}

func TestMatchPackageExternalSQL(t *testing.T) {
	for _, body := range []string{`db.Query(r.URL.Query().Get("q"))`, `q:=db.Query;q(r.URL.Query().Get("q"))`, `(*sql.DB).Query(db,r.URL.Query().Get("q"))`} {
		cg, _ := detailedGraphForSourceRoot(t, `package main
import ("database/sql";"net/http")
func handler(db *sql.DB,r *http.Request){`+body+`}
func main(){}`, "handler")
		src, sinks := NewSources("*net/http.Request"), NewSinks("(*database/sql.DB).Query")
		legacy := CheckDetailed(cg, src, sinks)
		got := CheckDetailed(cg, src, sinks, WithMatchPackages(cg.Root.Func.Pkg.Pkg))
		if len(legacy) != 1 || !reflect.DeepEqual(legacy, got) {
			t.Fatalf("SQL scope mismatch %s: %d/%d", body, len(legacy), len(got))
		}
	}
}

func TestMatchPackageNilSourceCall(t *testing.T) {
	for _, ctx := range []taintContext{newTaintContext(nil, 0), {matchPackages: map[*types.Package]struct{}{}}} {
		if _, ok := ctx.matchSourceCall(nil, nil); ok {
			t.Fatal("nil source call matched")
		}
	}
}

func TestMatchPackageInterfaceOccurrence(t *testing.T) {
	caller, _ := scopeProgram(t)
	fn := caller.Func("InterfaceSink")
	const api = "example.com/scope/api"
	src, sinks := NewSources(api+".Source"), NewSinks("(*"+api+".DB).Sink")
	// Preserve parity with the legacy resolver, whose concrete interface target
	// selection can vary when several synthetic method adapters are present.
	legacyGraph, err := callgraphutil.NewGraph(fn)
	if err != nil {
		t.Fatal(err)
	}
	legacy := CheckDetailed(legacyGraph, src, sinks)
	scoped := CheckDetailed(legacyGraph, src, sinks, WithMatchPackages(caller.Pkg))
	if !reflect.DeepEqual(legacy, scoped) {
		t.Fatal("legacy interface resolver scope mismatch")
	}
	// Independently pin the real interface call edge so this control requires a
	// finding and cannot pass vacuously when legacy resolution omitted it.
	graph := callgraph.New(fn)
	var found bool
	for _, block := range fn.Blocks {
		for _, instruction := range block.Instrs {
			call, ok := instruction.(*ssa.Call)
			if !ok || !call.Call.IsInvoke() {
				continue
			}
			pkg := caller.Prog.ImportedPackage(api)
			typ := types.NewPointer(pkg.Pkg.Scope().Lookup("DB").Type())
			target := caller.Prog.LookupMethod(typ, nil, "Sink")
			callgraph.AddEdge(graph.Root, call, graph.CreateNode(target))
			found = true
		}
	}
	if !found {
		t.Fatal("interface call missing")
	}
	if got := CheckDetailed(graph, src, sinks, WithMatchPackages(caller.Pkg)); len(got) != 1 {
		t.Fatalf("scoped interface got %d", len(got))
	}
	if got := CheckDetailed(graph, src, sinks, WithMatchPackages()); len(got) != 0 {
		t.Fatal("empty interface scope matched")
	}
}
