package callgraphutil_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/picatz/taint/callgraphutil"
)

func TestWriteCSV(t *testing.T) {
	var (
		ownerName = "picatz"
		repoName  = "taint"
	)

	repo, _, err := cloneGitHubRepository(context.Background(), ownerName, repoName)
	if err != nil {
		t.Fatal(err)
	}

	pkgs, err := loadPackages(context.Background(), repo, "./...")
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

	fh, err := os.Create(fmt.Sprintf("%s.csv", repoName))
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	err = callgraphutil.WriteCSV(fh, cg)
	if err != nil {
		t.Fatal(err)
	}
}
