package wholeprogram

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	sqli "github.com/picatz/taint/sql/injection"
	"golang.org/x/tools/go/packages"
)

func TestBodyCoverageSelectedOnly(t *testing.T) {
	dir, err := filepath.Abs("testdata/bodycoverage")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOWORK", "off")
	for _, tc := range []struct {
		name     string
		patterns []string
		missing  []string
		findings int
	}{
		{"helper omitted", []string{"./caller"}, []string{"example.com/bodycoverage/helper"}, 0},
		{"helper explicitly selected", []string{"./caller", "./helper"}, nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Load(context.Background(), Config{Dir: dir, Patterns: tc.patterns})
			if err != nil {
				t.Fatal(err)
			}
			c := p.BodyCoverage()
			if !reflect.DeepEqual(c.SameModuleDependencies, tc.missing) {
				t.Fatalf("coverage = %+v", c)
			}
			var blocks int
			for _, pkg := range p.SSA.AllPackages() {
				if pkg.Pkg.Path() == "example.com/bodycoverage/helper" {
					blocks = len(pkg.Func("Identity").Blocks)
				}
			}
			if (blocks == 0) != (len(tc.missing) != 0) {
				t.Fatalf("helper blocks = %d", blocks)
			}
			findings := sqli.Check(context.Background(), p.CallGraph)
			if len(findings) != tc.findings {
				t.Fatalf("findings = %v, want %d", findings, tc.findings)
			}
			// Reading the diagnostic cannot mutate findings or graph roots.
			entries := append([]string(nil), entryNames(p)...)
			again := p.BodyCoverage()
			if !reflect.DeepEqual(c, again) || !reflect.DeepEqual(entries, entryNames(p)) {
				t.Fatal("diagnostic changed state")
			}
		})
	}
}

func entryNames(p *Program) []string {
	var names []string
	for _, fn := range p.Entries {
		names = append(names, fn.String())
	}
	return names
}

func TestBodyCoverageModuleBoundaries(t *testing.T) {
	a := &packages.Module{Path: "example.com/a", Dir: "/work/a", GoMod: "/work/a/go.mod", Main: true}
	b := &packages.Module{Path: "example.com/b", Dir: "/work/b", GoMod: "/work/b/go.mod", Main: true}
	foreign := *a
	foreign.Dir = "/replacement/a"
	replacement := *a
	replacement.Replace = b
	makePkg := func(id string, m *packages.Module) *packages.Package { return &packages.Package{ID: id, Module: m} }
	first := makePkg("a", a)
	second := makePkg("b", b)
	first.Imports = map[string]*packages.Package{
		"z": makePkg("a/z", a), "a": makePkg("a/a", a),
		"workspace": makePkg("b/helper", b), "foreign": makePkg("foreign", &foreign),
		"replacement": makePkg("replacement", &replacement), "unknown": makePkg("unknown", nil),
	}
	p := &Program{Packages: []*packages.Package{first}}
	c := p.BodyCoverage()
	if !reflect.DeepEqual(c.SameModuleDependencies, []string{"a/a", "a/z"}) || c.OtherDependencies != 4 {
		t.Fatalf("coverage: %+v", c)
	}
	p.Packages = []*packages.Package{second, first, second}
	c = p.BodyCoverage()
	if !reflect.DeepEqual(c.SelectedPackages, []string{"a", "b"}) || !reflect.DeepEqual(c.SameModuleDependencies, []string{"a/a", "a/z", "b/helper"}) || c.OtherDependencies != 3 {
		t.Fatalf("coverage: %+v", c)
	}
	p.Packages = []*packages.Package{first, second}
	if !reflect.DeepEqual(c, p.BodyCoverage()) {
		t.Fatal("initial ordering changes coverage")
	}
}

func TestBodyCoverageWorkspace(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"go.work":            "go 1.26.0\nuse (\n ./a\n ./b\n)\n",
		"a/go.mod":           "module example.com/a\ngo 1.26.0\n",
		"a/caller/caller.go": "package caller\nimport (\"example.com/a/helper\"; \"example.com/b/helper\")\nvar X = helperA.Identity(helperB.Identity(\"value\"))\n",
		"a/helper/helper.go": "package helperA\nfunc Identity(s string) string { return s }\n",
		"b/go.mod":           "module example.com/b\ngo 1.26.0\n",
		"b/helper/helper.go": "package helperB\nfunc Identity(s string) string { return s }\n",
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
	t.Setenv("GOWORK", filepath.Join(dir, "go.work"))
	for _, tc := range []struct{ patterns, want []string }{
		{[]string{"./a/caller"}, []string{"example.com/a/helper"}},
		{[]string{"./a/caller", "./b/helper"}, []string{"example.com/a/helper"}},
	} {
		pkgs, err := packages.Load(&packages.Config{Dir: dir, Mode: loadMode}, tc.patterns...)
		if err != nil {
			t.Fatal(err)
		}
		if errs := LoadErrors(pkgs); len(errs) != 0 {
			t.Fatal(errs)
		}
		c := (&Program{Packages: pkgs}).BodyCoverage()
		if !reflect.DeepEqual(c.SameModuleDependencies, tc.want) {
			t.Fatalf("workspace coverage: %+v", c)
		}
		if len(tc.patterns) == 1 && c.OtherDependencies != 1 {
			t.Fatalf("unselected workspace sibling counted as same module: %+v", c)
		}
	}
}

func BenchmarkBodyCoverage(b *testing.B) {
	m := &packages.Module{Path: "example.com/module", Dir: "/module"}
	root := &packages.Package{ID: "root", Module: m, Imports: make(map[string]*packages.Package)}
	for i := 0; i < 1000; i++ {
		id := fmt.Sprintf("example.com/module/p%04d", i)
		root.Imports[id] = &packages.Package{ID: id, Module: m}
	}
	p := &Program{Packages: []*packages.Package{root}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.BodyCoverage()
	}
}

func TestSameModuleIdentity(t *testing.T) {
	base := packages.Module{Path: "example.com/a", Version: "v1.0.0", Dir: "/a", GoMod: "/a/go.mod"}
	equal := base
	equal.Main = true
	equal.Indirect = true
	if !sameModule(&base, &equal) {
		t.Fatal("equal identities with different metadata should match")
	}
	for _, mutate := range []func(*packages.Module){
		func(m *packages.Module) { m.Path = "example.com/b" },
		func(m *packages.Module) { m.Version = "v2.0.0" },
		func(m *packages.Module) { m.Dir = "/other" },
		func(m *packages.Module) { m.GoMod = "/other/go.mod" },
		func(m *packages.Module) { m.Replace = &packages.Module{Path: "../replacement", Dir: "/replacement"} },
	} {
		changed := base
		mutate(&changed)
		if sameModule(&base, &changed) {
			t.Errorf("different identity matched: %+v", changed)
		}
	}
	replacement := packages.Module{Path: "../replacement", Dir: "/replacement"}
	a, b := base, base
	a.Replace = &replacement
	copyReplacement := replacement
	b.Replace = &copyReplacement
	if !sameModule(&a, &b) {
		t.Fatal("equal replacement identities differ")
	}
	copyReplacement.Dir = "/different"
	if sameModule(&a, &b) {
		t.Fatal("different replacement identities matched")
	}
	b = a
	b.Path = "example.com/b"
	if sameModule(&a, &b) {
		t.Fatal("shared replacement merged original modules")
	}
	if sameModule(nil, nil) || sameModule(&packages.Module{Path: "example.com/a"}, &packages.Module{Path: "example.com/a"}) {
		t.Fatal("unknown identity matched")
	}
}

func TestBodyCoverageUnknownAndTransitive(t *testing.T) {
	m := &packages.Module{Path: "example.com/a", Dir: "/a"}
	leaf := &packages.Package{ID: "example.com/a/leaf", Module: m}
	middle := &packages.Package{ID: "example.com/a/middle", Module: m, Imports: map[string]*packages.Package{"leaf": leaf}}
	root := &packages.Package{ID: "example.com/a/root", Module: m, Imports: map[string]*packages.Package{"middle": middle}}
	variant := &packages.Package{ID: "example.com/a/root [example.com/a/root.test]", Module: m}
	unknown := &packages.Package{ID: "command-line-arguments", Module: &packages.Module{Path: "example.com/a"}}
	c := (&Program{Packages: []*packages.Package{root, variant, unknown}}).BodyCoverage()
	if !reflect.DeepEqual(c.SameModuleDependencies, []string{"example.com/a/leaf", "example.com/a/middle"}) || !reflect.DeepEqual(c.SelectedWithoutModuleIdentity, []string{"command-line-arguments"}) || len(c.SelectedPackages) != 3 {
		t.Fatalf("coverage: %+v", c)
	}
}

func TestBodyCoverageIncompleteReplacement(t *testing.T) {
	m := &packages.Module{Path: "example.com/a", Dir: "/a", Replace: &packages.Module{Path: "../a"}}
	p := &Program{Packages: []*packages.Package{{ID: "example.com/a", Module: m}}}
	if got := p.BodyCoverage().SelectedWithoutModuleIdentity; !reflect.DeepEqual(got, []string{"example.com/a"}) {
		t.Fatalf("incomplete replacement classified: %v", got)
	}
}
