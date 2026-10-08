package taint

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/picatz/taint/callgraphutil"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// The dependency deliberately has declarations but no SSA bodies, as with
// ssautil.Packages. Original, bound and expression methods coexist in AllFunctions.
func TestCheckDetailedInterfaceMethodAdapters(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.com/methods\ngo 1.26.0\n",
		"api/api.go": `package api
 type Printer struct{}
 type Print interface { Sink(string) }
 func (*Printer) Sink(string) {}
 func Source() string { return "input" }
 `,
		"caller/caller.go": `package caller
 import "example.com/methods/api"
 func Bound() { p:=new(api.Printer); f:=p.Sink; f(api.Source()) }
 func Expression() { p:=new(api.Printer); f:=(*api.Printer).Sink; f(p,api.Source()) }
 func Direct() { p:=new(api.Printer); p.Sink(api.Source()) }
 func Interface() { var p api.Print=new(api.Printer); p.Sink(api.Source()) }
 func Clean() { var p api.Print=new(api.Printer); p.Sink("safe") }
 func Unrelated() { _=api.Source(); var p api.Print=new(api.Printer); p.Sink("safe") }
 `,
	}
	for name, source := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOWORK", "off")
	pkgs, err := packages.Load(&packages.Config{Dir: dir, Mode: packages.LoadAllSyntax}, "./caller")
	if err != nil {
		t.Fatal(err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("package load failed")
	}
	prog, built := ssautil.Packages(pkgs, ssa.InstantiateGenerics)
	prog.Build()
	caller := built[0]
	for _, tc := range []struct {
		name string
		want int
	}{{"Interface", 1}, {"Direct", 1}, {"Bound", 1}, {"Expression", 1}, {"Clean", 0}, {"Unrelated", 0}} {
		t.Run(tc.name, func(t *testing.T) {
			cg, err := callgraphutil.NewGraph(caller.Func(tc.name))
			if err != nil {
				t.Fatal(err)
			}
			got := CheckDetailed(cg, NewSources("example.com/methods/api.Source"), NewSinks("(*example.com/methods/api.Printer).Sink"))
			if len(got) != tc.want {
				t.Fatalf("got %d diagnostics, want %d", len(got), tc.want)
			}
		})
	}
}
