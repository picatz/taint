package wholeprogram

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// A selected replaced module must admit its own transitive helper bodies while
// preserving selected roots. Unreachable helper exports are compiled, not roots.
func TestBodiesSelectedReplacement(t *testing.T) {
	t.Setenv("GOWORK", "off")
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":                       "module example.com/app\ngo 1.26.0\nrequire example.com/replaced v0.0.0\nreplace example.com/replaced => ./replacement\n",
		"caller/caller.go":             "package caller\nimport \"example.com/replaced\"\nfunc F()string{return replaced.F()}\n",
		"replacement/go.mod":           "module example.com/replaced\ngo 1.26.0\n",
		"replacement/root.go":          "package replaced\nimport \"example.com/replaced/helper\"\nfunc F()string{return helper.F()}\n",
		"replacement/helper/helper.go": "package helper\nimport \"example.com/replaced/leaf\"\nfunc F()string{return leaf.F()}\nfunc Unreachable()string{return \"unused\"}\n",
		"replacement/leaf/leaf.go":     "package leaf\nvar S string\nfunc init(){S=\"initialized\"}\nfunc F()string{return S}\n",
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
	cfg := Config{Dir: dir, Patterns: []string{"./caller", "example.com/replaced"}, Scope: ScopeSelected}
	base, err := Load(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Bodies = BodiesSameModule
	cfg.BodyLimits = BodyLimits{2, int64(len(files["replacement/helper/helper.go"]) + len(files["replacement/leaf/leaf.go"]))}
	expanded, err := Load(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(entryNames(base), entryNames(expanded)) {
		t.Fatalf("roots changed: %v / %v", entryNames(base), entryNames(expanded))
	}
	if len(expanded.Packages) != 2 || len(expanded.MatchPackages) != 2 {
		t.Fatal("selection widened")
	}
	for i, pkg := range expanded.Packages {
		if pkg.Types != expanded.MatchPackages[i] {
			t.Fatal("match identity changed")
		}
	}
	coverage := expanded.BodyCoverage()
	if !reflect.DeepEqual(coverage.BuiltSameModuleDependencies, []string{"example.com/replaced/helper", "example.com/replaced/leaf"}) || coverage.AdditionalSyntaxBytes != cfg.BodyLimits.MaxAdditionalSyntaxBytes {
		t.Fatalf("bad coverage: %+v", coverage)
	}
	for _, pkg := range expanded.SSA.AllPackages() {
		if pkg.Pkg.Path() == "example.com/replaced/helper" {
			for _, name := range []string{"F", "Unreachable"} {
				if fn := pkg.Func(name); fn == nil || len(fn.Blocks) == 0 {
					t.Fatalf("body absent: %s.%s", pkg.Pkg.Path(), name)
				}
			}
			for _, root := range expanded.Entries {
				if root == pkg.Func("Unreachable") {
					t.Fatal("helper export became root")
				}
			}
		}
		if pkg.Pkg.Path() == "example.com/replaced/leaf" {
			if node := expanded.CallGraph.Nodes[pkg.Func("init")]; node == nil {
				t.Fatal("imported initializer unreachable")
			}
		}
	}
}
