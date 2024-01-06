package callgraphutil_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/picatz/taint/callgraphutil"
)

func TestWriteCosmograph(t *testing.T) {
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

	graphOutput, err := os.Create(fmt.Sprintf("%s.csv", repoName))
	if err != nil {
		t.Fatal(err)
	}
	defer graphOutput.Close()

	metadataOutput, err := os.Create(fmt.Sprintf("%s-metadata.csv", repoName))
	if err != nil {
		t.Fatal(err)
	}
	defer metadataOutput.Close()

	err = callgraphutil.WriteCosmograph(graphOutput, metadataOutput, cg)
	if err != nil {
		t.Fatal(err)
	}
}
