package callgraphutil

import (
	"context"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/ssa"
)

func TestParseCallGraphAlgorithm(t *testing.T) {
	tests := []struct {
		name string
		want CallGraphAlgorithm
	}{
		{"", CallGraphAlgorithmTaint},
		{"taint", CallGraphAlgorithmTaint},
		{"custom", CallGraphAlgorithmTaint},
		{"vta", CallGraphAlgorithmVTA},
		{"vulncheck", CallGraphAlgorithmVTA},
	}

	for _, test := range tests {
		got, err := ParseCallGraphAlgorithm(test.name)
		if err != nil {
			t.Fatalf("ParseCallGraphAlgorithm(%q): %v", test.name, err)
		}
		if got != test.want {
			t.Fatalf("ParseCallGraphAlgorithm(%q) = %q, want %q", test.name, got, test.want)
		}
	}

	if _, err := ParseCallGraphAlgorithm("unknown"); err == nil {
		t.Fatal("expected unsupported algorithm error")
	}
}

func TestBuildCallGraphRejectsUnsupportedAlgorithm(t *testing.T) {
	prog := ssa.NewProgram(token.NewFileSet(), ssa.InstantiateGenerics)
	sig := types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false)
	root := prog.NewFunction("root", sig, "test")

	if _, _, err := BuildCallGraph(context.Background(), "unknown", prog, root, []*ssa.Function{root}); err == nil {
		t.Fatal("expected unsupported algorithm error")
	}
}

func TestBuildCallGraphUsesTaintAlgorithm(t *testing.T) {
	prog := ssa.NewProgram(token.NewFileSet(), ssa.InstantiateGenerics)
	sig := types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false)
	root := prog.NewFunction("root", sig, "test")
	target := prog.NewFunction("target", sig, "test")

	cg, gotRoot, err := BuildCallGraph(context.Background(), CallGraphAlgorithmTaint, prog, root, []*ssa.Function{root, target})
	if err != nil {
		t.Fatal(err)
	}
	if gotRoot != root {
		t.Fatalf("root = %v, want %v", gotRoot, root)
	}
	if cg == nil || cg.Root == nil || cg.Root.Func != root {
		t.Fatalf("unexpected graph root: %#v", cg)
	}
}

func TestBuildCallGraphUsesVTAAlgorithm(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/vtatest\n\ngo 1.24.4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main

func target() {}
func main() { target() }
`), 0o644); err != nil {
		t.Fatal(err)
	}

	pkgs, err := loadPackages(context.Background(), dir, "./...")
	if err != nil {
		t.Fatal(err)
	}
	mainFn, srcFns, err := loadSSA(context.Background(), pkgs)
	if err != nil {
		t.Fatal(err)
	}

	cg, gotRoot, err := BuildCallGraph(context.Background(), CallGraphAlgorithmVTA, mainFn.Prog, mainFn, srcFns)
	if err != nil {
		t.Fatal(err)
	}
	if gotRoot != mainFn {
		t.Fatalf("root = %v, want %v", gotRoot, mainFn)
	}
	if cg == nil || cg.Root == nil || cg.Root.Func != mainFn {
		t.Fatalf("unexpected VTA graph root: %#v", cg)
	}
}
