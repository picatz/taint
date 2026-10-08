package taint

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"
	"strings"
	"testing"

	"github.com/picatz/taint/callgraphutil"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

func TestCheckDetailedPhysicalDiagnosticOrder(t *testing.T) {
	files := map[string]string{
		"a.go":   "package order\nfunc A(){Sink(Source())}\n",
		"b.go":   "package order\nfunc B(){Sink(Source())}\n",
		"c.go":   "package order\nfunc C(){Sink(Source())}\n",
		"api.go": "package order\nfunc Source()string{return \"input\"}\nfunc Sink(string){}\n",
	}
	build := func(order []string, scoped, directives bool) []string {
		fs := token.NewFileSet()
		asts := make(map[string]*ast.File)
		for _, n := range order {
			source := files[n]
			if directives && n != "api.go" {
				source = strings.Replace(source, "\n", "\n//line virtual.go:1\n", 1)
			}
			f, e := parser.ParseFile(fs, n, source, 0)
			if e != nil {
				t.Fatal(e)
			}
			asts[n] = f
		}
		// Keep logical compilation input order fixed, vary only file-set allocation.
		syntax := []*ast.File{asts["a.go"], asts["b.go"], asts["c.go"], asts["api.go"]}
		info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}, Implicits: map[ast.Node]types.Object{}, Scopes: map[ast.Node]*types.Scope{}, Selections: map[*ast.SelectorExpr]*types.Selection{}}
		tp, e := new(types.Config).Check("example.com/order", fs, syntax, info)
		if e != nil {
			t.Fatal(e)
		}
		prog := ssa.NewProgram(fs, ssa.InstantiateGenerics)
		p := prog.CreatePackage(tp, syntax, info, true)
		prog.Build()
		cg, _, e := callgraphutil.CreateCallGraphFromEntries(context.Background(), prog, []*ssa.Function{p.Func("A"), p.Func("B"), p.Func("C")})
		if e != nil {
			t.Fatal(e)
		}
		var opts []Option
		if scoped {
			opts = append(opts, WithMatchPackages(tp))
		}
		got := CheckDetailed(cg, NewSources("example.com/order.Source"), NewSinks("example.com/order.Sink"), opts...)
		var names []string
		for _, v := range got {
			names = append(names, fs.PositionFor(v.Result.ReportPos(), false).Filename)
			if directives && fs.Position(v.Result.ReportPos()).Filename != "virtual.go" {
				t.Fatal("fixture lacks adjusted-position collision")
			}
		}
		return names
	}
	for _, tc := range []struct {
		name       string
		scoped     bool
		directives bool
	}{{"default", false, false}, {"selected", true, false}, {"default line directives", false, true}, {"selected line directives", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			first := build([]string{"a.go", "b.go", "c.go", "api.go"}, tc.scoped, tc.directives)
			if !reflect.DeepEqual(first, []string{"a.go", "b.go", "c.go"}) {
				t.Fatalf("positive control findings = %v", first)
			}
			second := build([]string{"c.go", "b.go", "a.go", "api.go"}, tc.scoped, tc.directives)
			if !reflect.DeepEqual(first, second) {
				t.Fatalf("equivalent program diagnostic order changed: %v to %v", first, second)
			}
		})
	}
}

// The embedded interfaces supply methods that these location-only fixtures do
// not need. Only Pos and Parent are read by the diagnostic-order comparator.
type diagnosticOrderValue struct {
	ssa.Value
	fn  *ssa.Function
	pos token.Pos
}

func (v diagnosticOrderValue) Pos() token.Pos        { return v.pos }
func (v diagnosticOrderValue) Parent() *ssa.Function { return v.fn }

type diagnosticOrderCall struct {
	ssa.CallInstruction
	fn  *ssa.Function
	pos token.Pos
}

func (c diagnosticOrderCall) Pos() token.Pos        { return c.pos }
func (c diagnosticOrderCall) Parent() *ssa.Function { return c.fn }

func TestDiagnosticLocationFallbacks(t *testing.T) {
	fs := token.NewFileSet()
	file := fs.AddFile("real.go", 100, 40)
	file.AddLineColumnInfo(0, "virtual.go", 99, 1)
	prog := ssa.NewProgram(fs, 0)
	fn := prog.NewFunction("F", nil, "")
	value := diagnosticOrderValue{fn: fn, pos: token.Pos(123)}
	call := diagnosticOrderCall{fn: fn, pos: token.Pos(110)}
	path := callgraphutil.Path{&callgraph.Edge{Site: call}}
	for _, tc := range []struct {
		name     string
		result   Result
		filename string
		offset   int
	}{
		{"zero", Result{}, "", 0},
		{"sink value", Result{SinkValue: value}, "real.go", 23},
		{"path precedes value", Result{Path: path, SinkValue: value}, "real.go", 10},
		{"skip positionless and nil edges", Result{Path: append(append(callgraphutil.Path{}, path...), nil, &callgraph.Edge{}, &callgraph.Edge{Site: diagnosticOrderCall{fn: fn}}), SinkValue: value}, "real.go", 10},
		{"positionless path uses value", Result{Path: callgraphutil.Path{&callgraph.Edge{Site: diagnosticOrderCall{fn: fn}}}, SinkValue: value}, "real.go", 23},
		{"nil owner", Result{SinkValue: diagnosticOrderValue{pos: 7}}, "", 7},
		{"nil program", Result{SinkValue: diagnosticOrderValue{fn: &ssa.Function{}, pos: 7}}, "", 7},
		{"nil file set", Result{SinkValue: diagnosticOrderValue{fn: ssa.NewProgram(nil, 0).NewFunction("F", nil, ""), pos: 7}}, "", 7},
		{"position outside file set", Result{SinkValue: diagnosticOrderValue{fn: fn, pos: 999}}, "", 999},
		{"unknown path owner does not borrow value program", Result{Path: callgraphutil.Path{&callgraph.Edge{Site: diagnosticOrderCall{pos: 110}}}, SinkValue: value}, "", 110},
	} {
		t.Run(tc.name, func(t *testing.T) {
			filename, offset := diagnosticLocation(tc.result)
			if filename != tc.filename || offset != tc.offset {
				t.Fatalf("location=(%q,%d), want (%q,%d)", filename, offset, tc.filename, tc.offset)
			}
		})
	}
	if got := fs.Position(value.pos).Filename; got != "virtual.go" {
		t.Fatalf("line-directive control=%q", got)
	}
}

func TestDiagnosticOrderTieBreaks(t *testing.T) {
	makeDiagnostic := func(base, offset int, filename, source, sink string) Diagnostic {
		fs := token.NewFileSet()
		file := fs.AddFile(filename, base, 40)
		fn := ssa.NewProgram(fs, 0).NewFunction("F", nil, "")
		return Diagnostic{Result: Result{SinkValue: diagnosticOrderValue{fn: fn, pos: file.Pos(offset)}, SourceType: source, SinkType: sink}}
	}
	cases := []struct {
		name          string
		first, second Diagnostic
	}{
		{"physical filename before raw base", makeDiagnostic(100, 1, "a.go", "Z", "Z"), makeDiagnostic(1, 1, "b.go", "A", "A")},
		{"offset before type", makeDiagnostic(100, 1, "a.go", "Z", "Z"), makeDiagnostic(1, 2, "a.go", "A", "A")},
		{"source before raw base", makeDiagnostic(100, 1, "a.go", "A", "Z"), makeDiagnostic(1, 1, "a.go", "B", "A")},
		{"sink before raw base", makeDiagnostic(100, 1, "a.go", "A", "A"), makeDiagnostic(1, 1, "a.go", "A", "B")},
		{"equal physical locations retain distinct variants", makeDiagnostic(1, 1, "a.go", "A", "A"), makeDiagnostic(100, 1, "a.go", "A", "A")},
		{"unresolved positions retain numeric order", Diagnostic{Result: Result{SinkValue: diagnosticOrderValue{pos: 1}, SourceType: "Z"}}, Diagnostic{Result: Result{SinkValue: diagnosticOrderValue{pos: 2}, SourceType: "A"}}},
		{"zero before located", Diagnostic{}, makeDiagnostic(1, 1, "a.go", "A", "A")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if compareDiagnostics(tc.first, tc.second) >= 0 || compareDiagnostics(tc.second, tc.first) <= 0 {
				t.Fatal("asymmetric ordering failed")
			}
			if compareDiagnostics(tc.first, tc.first) != 0 {
				t.Fatal("reflexive ordering failed")
			}
		})
	}
}
