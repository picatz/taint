package wholeprogram_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/picatz/taint"
	"github.com/picatz/taint/internal/wholeprogram"
	logi "github.com/picatz/taint/log/injection"
)

func scopeAdversarialFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	t.Setenv("GOWORK", "off")
	d := t.TempDir()
	files["go.mod"] = "module example.com/review\ngo 1.26.0\n"
	for n, s := range files {
		p := filepath.Join(d, n)
		if e := os.MkdirAll(filepath.Dir(p), 0755); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(p, []byte(s), 0600); e != nil {
			t.Fatal(e)
		}
	}
	return d
}
func TestProfileSelectedMainInitAndDeadCode(t *testing.T) {
	d := scopeAdversarialFixture(t, map[string]string{
		"cmd/main.go": `package main
 import("net/http";"log";"example.com/review/helper")
 var r *http.Request
 var _ = func() int { log.Print(r.FormValue("initialization")); return 0 }()
 func main(){helper.Run(r)}
 func Dead(){log.Print(r.FormValue("dead"))}`,
		"helper/helper.go": `package helper
 import("net/http";"log")
 func Run(r *http.Request){log.Print(r.FormValue("helper"))}
 func Dead(r *http.Request){log.Print(r.FormValue("deadhelper"))}`,
	})
	for _, tc := range []struct {
		patterns []string
		want     int
	}{{[]string{"./cmd"}, 1}, {[]string{"./cmd", "./helper"}, 2}} {
		p, e := wholeprogram.Load(context.Background(), wholeprogram.Config{Dir: d, Patterns: tc.patterns, Scope: wholeprogram.ScopeSelected})
		if e != nil {
			t.Fatal(e)
		}
		got := logi.CheckWithOptions(context.Background(), p.CallGraph, taint.WithMatchPackages(p.MatchPackages...))
		if len(got) != tc.want {
			t.Errorf("%v: findings=%v want %d", tc.patterns, got, tc.want)
		}
	}
}
func TestProfileSelectedGenericTypeAndTestIdentities(t *testing.T) {
	d := scopeAdversarialFixture(t, map[string]string{
		"lib.go": `package review
 import("log";"net/http")
 type Generic[T ~string] struct{ V T }
 func (g Generic[T]) Run(r *http.Request){ log.Print(r.FormValue(string(g.V))) }
 func GenericCall(r *http.Request){Generic[string]{V:"q"}.Run(r)}
 func Handler(r *http.Request){log.Print(r.FormValue("normal"))}`,
		"lib_test.go": `package review
 import("testing";"net/http";"log")
 func TestHandler(t *testing.T){var r *http.Request;log.Print(r.FormValue("test"))}`,
	})
	for _, tests := range []bool{false, true} {
		p, e := wholeprogram.Load(context.Background(), wholeprogram.Config{Dir: d, Patterns: []string{"."}, Tests: tests, Scope: wholeprogram.ScopeSelected})
		if e != nil {
			t.Fatal(e)
		}
		selected := map[string]int{}
		for _, pkg := range p.Packages {
			selected[pkg.PkgPath]++
			found := false
			for _, identity := range p.MatchPackages {
				if identity == pkg.Types {
					found = true
				}
			}
			if !found {
				t.Fatal("lost original identity", pkg.ID)
			}
		}
		if tests && selected["example.com/review"] < 2 {
			t.Fatal("expected distinct same-path test identities", selected)
		}
		got := logi.CheckWithOptions(context.Background(), p.CallGraph, taint.WithMatchPackages(p.MatchPackages...))
		if !tests && len(got) == 0 {
			t.Fatalf("tests=%v no positive findings", tests)
		}
		t.Logf("tests=%v entries=%v findings=%v", tests, p.Entries, got)
		if tests {
			legacy, e := wholeprogram.Load(context.Background(), wholeprogram.Config{Dir: d, Patterns: []string{"."}, Tests: true})
			if e != nil {
				t.Fatal(e)
			}
			t.Logf("legacy test findings=%v", logi.Check(context.Background(), legacy.CallGraph))
			for _, entry := range p.Entries {
				if !strings.HasSuffix(entry.String(), ".main") && !strings.HasSuffix(entry.String(), ".init") {
					t.Error("test main must dominate library roots", entry)
				}
			}
		}
	}
}
func TestProfilePromotedAdapterRootOwnership(t *testing.T) {
	d := scopeAdversarialFixture(t, map[string]string{
		"dep/dep.go": `package dep
 type Foreign struct{}
 func (Foreign) Sink(s string) {}`,
		"lib/lib.go": `package lib
 import("example.com/review/dep";"net/http")
 type API struct{dep.Foreign}
 func RealCall(r *http.Request){ var a API; a.Sink(r.FormValue("real")) }`,
	})
	p, e := wholeprogram.Load(context.Background(), wholeprogram.Config{Dir: d, Patterns: []string{"./lib"}, Scope: wholeprogram.ScopeSelected})
	if e != nil {
		t.Fatal(e)
	}
	sources := taint.NewSources("*example.com/review/lib.API", "example.com/review/lib.API", "*net/http.Request", "string")
	sinks := taint.NewSinks("(example.com/review/dep.Foreign).Sink")
	all := taint.CheckDetailed(p.CallGraph, sources, sinks)
	scoped := taint.CheckDetailed(p.CallGraph, sources, sinks, taint.WithMatchPackages(p.MatchPackages...))
	t.Logf("unscoped=%d scoped=%d", len(all), len(scoped))
	for _, d := range all {
		t.Logf("unscoped path: %v", d.Result.Path)
	}
	for _, d := range scoped {
		t.Logf("scoped path: %v", d.Result.Path)
	}
	for _, diagnostic := range scoped {
		selectedCall := false
		for _, edge := range diagnostic.Result.Path {
			if edge.Site != nil && edge.Site.Parent().String() == "example.com/review/lib.RealCall" {
				selectedCall = true
			}
		}
		if !selectedCall {
			t.Error("scoped finding lacks a real selected callsite", diagnostic.Result.Path)
		}
	}
	if len(scoped) != 1 {
		t.Errorf("selected real call should survive exactly once; got %d", len(scoped))
	}
	if len(all) <= len(scoped) {
		t.Error("no positive control for excluded synthetic root")
	}
}
