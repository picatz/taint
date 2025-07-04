package callgraphutil_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/picatz/taint/callgraphutil"
)

func TestStructFieldCallGraph(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("testdata"))
	if err != nil {
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

	cg, err := loadCallGraph(context.Background(), mainFn, srcFns)
	if err != nil {
		t.Fatal(err)
	}

	target := "github.com/picatz/taint/callgraphutil/testdata.doSomething"
	if paths := callgraphutil.PathsSearchCallTo(cg.Root, target); len(paths) == 0 {
		t.Fatalf("expected path to %s", target)
	}
}
