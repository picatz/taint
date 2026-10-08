package callgraphutil

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func methodResolutionFixture(t *testing.T) (*ssa.Program, *ssa.Package) {
	t.Helper()
	const source = `package methods
 type Sink interface { Send(string) }
 type Value struct{}
 func (Value) Send(string) {}
 type Pointer struct{}
 func (*Pointer) Send(string) {}
 type Embedded struct { Pointer }
 type EmbeddedPointer struct { *Pointer }
 type Generic[T any] struct { value T }
 func (*Generic[T]) Send(string) {}
 type Missing struct{}
 func (*Missing) Send(string)
 func Adapters(p *Pointer, g *Generic[int]) {
  bound:=p.Send; bound("safe")
  expr:=(*Pointer).Send; expr(p,"safe")
  gb:=g.Send; gb("safe")
  ge:=(*Generic[int]).Send; ge(g,"safe")
 }
 func ValueInvoke() { var s Sink=Value{}; s.Send("safe") }
 func PointerValueInvoke() { var s Sink=new(Value); s.Send("safe") }
 func PointerInvoke() { var s Sink=new(Pointer); s.Send("safe") }
 func EmbeddedInvoke() { var s Sink=new(Embedded); s.Send("safe") }
 func EmbeddedPointerInvoke() { var s Sink=EmbeddedPointer{new(Pointer)}; s.Send("safe") }
 func GenericInvoke() { var s Sink=new(Generic[int]); s.Send("safe") }
 func MissingInvoke() { var s Sink=new(Missing); s.Send("safe") }
 func UnknownInvoke(s Sink) { s.Send("safe") }
 `
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "methods.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}, Implicits: map[ast.Node]types.Object{}, Scopes: map[ast.Node]*types.Scope{}, Selections: map[*ast.SelectorExpr]*types.Selection{}, Instances: map[*ast.Ident]types.Instance{}}
	pkg, err := new(types.Config).Check("example.com/methods", fset, []*ast.File{file}, info)
	if err != nil {
		t.Fatal(err)
	}
	prog := ssa.NewProgram(fset, ssa.InstantiateGenerics)
	sp := prog.CreatePackage(pkg, []*ast.File{file}, info, true)
	prog.Build()
	return prog, sp
}

func TestInterfaceMethodResolutionUsesReceiverSelection(t *testing.T) {
	prog, pkg := methodResolutionFixture(t)
	// Enumerate adapters before constructing the graph, as the real prepass does.
	all := ssautil.AllFunctions(prog)
	pointer := pkg.Pkg.Scope().Lookup("Pointer").Type()
	object := prog.MethodSets.MethodSet(types.NewPointer(pointer)).Lookup(pkg.Pkg, "Send").Obj()
	adapters := 0
	for fn := range all {
		if fn.Object() == object {
			adapters++
		}
	}
	if adapters < 3 {
		t.Fatalf("fixture has %d method variants, want original, bound and thunk", adapters)
	}
	for _, name := range []string{"ValueInvoke", "PointerValueInvoke", "PointerInvoke", "EmbeddedInvoke", "EmbeddedPointerInvoke", "GenericInvoke", "MissingInvoke"} {
		t.Run(name, func(t *testing.T) {
			caller := pkg.Func(name)
			var invoke ssa.CallInstruction
			for _, block := range caller.Blocks {
				for _, ins := range block.Instrs {
					if c, ok := ins.(ssa.CallInstruction); ok && c.Common().IsInvoke() {
						invoke = c
					}
				}
			}
			if invoke == nil {
				t.Fatal("missing invoke")
			}
			receiver := invoke.Common().Value.(*ssa.MakeInterface).X.Type()
			selection := prog.MethodSets.MethodSet(receiver).Lookup(pkg.Pkg, "Send")
			want := prog.MethodValue(selection)
			if want == nil {
				t.Fatal("missing canonical method")
			}
			targets := resolveCallTargets(prog, invoke.Common())
			if len(targets) != 1 || targets[0] != want {
				t.Fatalf("targets %v, want only %s", targets, want)
			}
			if want.Signature.Recv() == nil || !types.Identical(want.Signature.Recv().Type(), receiver) || len(want.FreeVars) != 0 {
				t.Fatalf("wrong receiver convention: %s", want)
			}
			if name == "MissingInvoke" && len(want.Blocks) != 0 {
				t.Fatal("declaration acquired a body")
			}
			if name == "GenericInvoke" && (len(want.TypeArgs()) != 1 || !types.Identical(want.TypeArgs()[0], types.Typ[types.Int])) {
				t.Fatalf("wrong instance: %s", want)
			}
			if (name == "PointerValueInvoke" || name == "EmbeddedInvoke" || name == "EmbeddedPointerInvoke") && want.Synthetic == "" {
				t.Fatal("missing required adapter")
			}
			graph, err := NewGraph(caller)
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, edge := range graph.Nodes[caller].Out {
				if edge.Site == invoke {
					count++
					if edge.Callee.Func != want {
						t.Fatalf("wrong invoke edge: %s", edge.Callee.Func)
					}
				}
			}
			if count != 1 {
				t.Fatalf("got %d invoke edges, want one", count)
			}
		})
	}
}

func TestInterfaceMethodResolutionDoesNotInventReceivers(t *testing.T) {
	prog, pkg := methodResolutionFixture(t)
	pointer := pkg.Pkg.Scope().Lookup("Pointer").Type()
	method := prog.MethodSets.MethodSet(types.NewPointer(pointer)).Lookup(pkg.Pkg, "Send").Obj().(*types.Func)
	for _, receiver := range []types.Type{pointer, pkg.Pkg.Scope().Lookup("Sink").Type(), types.NewPointer(pkg.Pkg.Scope().Lookup("Generic").Type())} {
		if got := concreteMethodsForInvoke(prog, receiver, method); len(got) != 0 {
			t.Fatalf("invented targets for %s: %v", receiver, got)
		}
	}
}
