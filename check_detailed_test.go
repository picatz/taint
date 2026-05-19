package taint

import (
	"context"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"testing"

	"github.com/picatz/taint/callgraphutil"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func TestCheckDetailedEvidenceOrder(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func wrapper(q string) string { return q }

func main() {
	db := &sql.DB{}
	db.Query(wrapper(source()))
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected one diagnostic, got %d", len(diagnostics))
	}

	gotKinds := evidenceKinds(diagnostics[0].Evidence)
	assertEvidenceOrder(t, gotKinds, EvidenceSourceMatch, EvidenceSinkMatch)
	assertEvidenceContains(t, gotKinds, EvidenceParameterMapping)
	assertEvidenceContains(t, gotKinds, EvidencePropagationStep)
	assertEvidenceContains(t, gotKinds, EvidenceSanitizerRejected)
}

func TestCheckDetailedAppliesValueSpecificSanitizer(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"html"
)

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	db.Query(html.EscapeString(source()))
}
`)

	withoutSanitizer := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(withoutSanitizer) != 1 {
		t.Fatalf("expected unsanitized check to report one diagnostic, got %d", len(withoutSanitizer))
	}

	withSanitizer := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
		WithSanitizers("html.EscapeString"),
	)
	if len(withSanitizer) != 0 {
		t.Fatalf("expected sanitizer to suppress diagnostic, got %d", len(withSanitizer))
	}
}

func TestCheckDetailedExtraSourcesAndSinks(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	db.Query(source())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(),
		NewSinks(),
		WithExtraSources(pkgPath+".source"),
		WithExtraSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected extra source/sink options to report one diagnostic, got %d", len(diagnostics))
	}
}

func TestSourceRegistryMatchesTypes(t *testing.T) {
	pkg := types.NewPackage("net/http", "http")
	obj := types.NewTypeName(token.NoPos, pkg, "Request", nil)
	request := types.NewNamed(obj, types.NewStruct(nil, nil), nil)

	if src, ok := matchSourceType(NewSources("*net/http.Request"), types.NewPointer(request)); !ok || src != "*net/http.Request" {
		t.Fatalf("expected *net/http.Request source match, got %q matched=%v", src, ok)
	}
}

func evidenceKinds(evidence []Evidence) []EvidenceKind {
	kinds := make([]EvidenceKind, 0, len(evidence))
	for _, entry := range evidence {
		kinds = append(kinds, entry.Kind)
	}
	return kinds
}

func assertEvidenceContains(t *testing.T, kinds []EvidenceKind, want EvidenceKind) {
	t.Helper()
	for _, kind := range kinds {
		if kind == want {
			return
		}
	}
	t.Fatalf("expected evidence kind %s in %v", want, kinds)
}

func assertEvidenceOrder(t *testing.T, kinds []EvidenceKind, first, second EvidenceKind) {
	t.Helper()
	firstIndex, secondIndex := -1, -1
	for i, kind := range kinds {
		if kind == first && firstIndex < 0 {
			firstIndex = i
		}
		if kind == second && secondIndex < 0 {
			secondIndex = i
		}
	}
	if firstIndex < 0 || secondIndex < 0 {
		t.Fatalf("expected evidence kinds %s and %s in %v", first, second, kinds)
	}
	if firstIndex >= secondIndex {
		t.Fatalf("expected %s before %s in %v", first, second, kinds)
	}
}

func detailedGraphForSource(t *testing.T, src string) (*callgraph.Graph, string) {
	t.Helper()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/detailed\n\ngo 1.24.4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	pkgs, err := packages.Load(&packages.Config{
		Mode: packages.NeedName |
			packages.NeedDeps |
			packages.NeedFiles |
			packages.NeedCompiledGoFiles |
			packages.NeedTypes |
			packages.NeedImports |
			packages.NeedSyntax |
			packages.NeedTypesInfo,
		Context: context.Background(),
		Dir:     dir,
		Tests:   false,
	}, "./...")
	if err != nil {
		t.Fatal(err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("package load failed")
	}

	ssaProg, ssaPkgs := ssautil.Packages(pkgs, ssa.InstantiateGenerics)
	ssaProg.Build()
	for _, pkg := range ssaPkgs {
		pkg.Build()
	}

	mainPkgs := ssautil.MainPackages(ssaPkgs)
	if len(mainPkgs) != 1 {
		t.Fatalf("expected one main package, got %d", len(mainPkgs))
	}
	mainFn := mainPkgs[0].Func("main")
	if mainFn == nil {
		t.Fatal("main function not found")
	}

	var srcFns []*ssa.Function
	var addFunction func(*ssa.Function)
	addFunction = func(fn *ssa.Function) {
		srcFns = append(srcFns, fn)
		for _, anon := range fn.AnonFuncs {
			addFunction(anon)
		}
	}
	for _, pkg := range ssaPkgs {
		for _, member := range pkg.Members {
			fn, ok := member.(*ssa.Function)
			if !ok || fn.Object() == nil || fn.Object().Name() == "_" {
				continue
			}
			addFunction(fn)
		}
	}

	cg, err := callgraphutil.NewGraph(mainFn, srcFns...)
	if err != nil {
		t.Fatal(err)
	}
	return cg, mainFn.Pkg.Pkg.Path()
}
