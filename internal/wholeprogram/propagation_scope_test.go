package wholeprogram

import (
	"context"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/picatz/taint"
)

func TestSelectedProfileHelperBodyAndOccurrenceBoundaries(t *testing.T) {
	t.Setenv("GOWORK", "off")
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.com/selectedflow\ngo 1.26.0\n",
		"api/api.go": `package api
 func Source() string {return "input"}
 func Sink(string){}
 func Clean(s string)string{return s}
 `,
		"helper/helper.go": `package helper
 import "example.com/selectedflow/api"
 func Identity(s string) string{return s}
 func Constant(s string) string{return "safe"}
 func OwnSource() string{return api.Source()}
 func OwnSink(s string){api.Sink(s)}
 func Sanitize(s string)string{return api.Clean(s)}
 `,
		"caller/caller.go": `package caller
 import("example.com/selectedflow/api";"example.com/selectedflow/helper")
 func Direct(){api.Sink(api.Source())}
 func Propagate(){api.Sink(helper.Identity(api.Source()))}
 func Constant(){api.Sink(helper.Constant(api.Source()))}
 func HelperSource(){api.Sink(helper.OwnSource())}
 func HelperSink(){helper.OwnSink(api.Source())}
 func Sanitized(){api.Sink(helper.Sanitize(api.Source()))}
 `,
	}
	for name, src := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0600); err != nil {
			t.Fatal(err)
		}
	}
	model := taint.WithModels(taint.Model{
		Sources:    []taint.SourceModel{{Call: "example.com/selectedflow/api.Source"}},
		Sinks:      []taint.SinkModel{{Method: "example.com/selectedflow/api.Sink"}},
		Sanitizers: []taint.SanitizerModel{{Func: "example.com/selectedflow/api.Clean"}},
	})
	check := func(p *Program, pkgs []*types.Package) map[string]int {
		t.Helper()
		got := map[string]int{}
		for _, d := range taint.CheckDetailed(p.CallGraph, nil, nil, model, taint.WithMatchPackages(pkgs...)) {
			path := d.Result.Path
			edge := path[len(path)-1]
			if edge.Site == nil {
				t.Fatal("finding lacks occurrence")
			}
			got[edge.Site.Parent().Name()]++
		}
		return got
	}
	omitted, err := Load(context.Background(), Config{Dir: dir, Patterns: []string{"./caller"}, Scope: ScopeSelected})
	if err != nil {
		t.Fatal(err)
	}
	if got := check(omitted, omitted.MatchPackages); !reflect.DeepEqual(got, map[string]int{"Direct": 1}) {
		t.Fatalf("unselected opaque helper: %v", got)
	}
	expanded, err := Load(context.Background(), Config{Dir: dir, Patterns: []string{"./caller"}, Scope: ScopeSelected, Bodies: BodiesSameModule, BodyLimits: BodyLimits{MaxAdditionalPackages: 2, MaxAdditionalSyntaxBytes: 10000}})
	if err != nil {
		t.Fatal(err)
	}
	if got := check(expanded, expanded.MatchPackages); !reflect.DeepEqual(got, map[string]int{"Direct": 1, "Propagate": 1}) {
		t.Fatalf("same-module occurrence scope: %v", got)
	}
	if !reflect.DeepEqual(entryNames(omitted), entryNames(expanded)) {
		t.Fatalf("body expansion changed roots: %v / %v", entryNames(omitted), entryNames(expanded))
	}
	if len(expanded.Packages) != 1 || len(expanded.MatchPackages) != 1 || expanded.MatchPackages[0] != expanded.Packages[0].Types {
		t.Fatal("body expansion changed selected identities")
	}
	loaded, err := Load(context.Background(), Config{Dir: dir, Patterns: []string{"./caller", "./helper"}, Scope: ScopeSelected})
	if err != nil {
		t.Fatal(err)
	}
	if got := check(loaded, loaded.MatchPackages); !reflect.DeepEqual(got, map[string]int{"Direct": 1, "Propagate": 1, "HelperSource": 1, "OwnSink": 1}) {
		t.Fatalf("explicitly selected helper: %v", got)
	}
	// With both bodies available, a narrower occurrence option must retain
	// propagation and sanitization without reseeding helper-owned sources/sinks.
	// This is a detector/API seam control, not a different loader body profile.
	var caller *types.Package
	for _, p := range loaded.Packages {
		if p.Name == "caller" {
			caller = p.Types
		}
	}
	if caller == nil {
		t.Fatal("caller package absent")
	}
	if got := check(loaded, []*types.Package{caller}); !reflect.DeepEqual(got, map[string]int{"Direct": 1, "Propagate": 1}) {
		t.Fatalf("narrow occurrence scope: %v", got)
	}
}
