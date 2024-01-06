package callgraphutil_test

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/picatz/taint/callgraphutil"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func cloneGitHubRepository(ctx context.Context, ownerName, repoName string) (string, string, error) {
	// Get the owner and repo part of the URL.
	ownerAndRepo := ownerName + "/" + repoName

	// Get the directory path.
	dir := filepath.Join(os.TempDir(), "taint", "github", ownerAndRepo)

	// Check if the directory exists.
	_, err := os.Stat(dir)
	if err == nil {
		// If the directory exists, we'll assume it's a valid repository,
		// and return the directory. Open the directory to
		repo, err := git.PlainOpen(dir)
		if err != nil {
			return dir, "", fmt.Errorf("%w", err)
		}

		// Get the repository's HEAD.
		head, err := repo.Head()
		if err != nil {
			return dir, "", fmt.Errorf("%w", err)
		}

		return dir, head.Hash().String(), nil
	}

	// Clone the repository.
	repo, err := git.PlainCloneContext(ctx, dir, false, &git.CloneOptions{
		URL:          fmt.Sprintf("https://github.com/%s", ownerAndRepo),
		Depth:        1,
		Tags:         git.NoTags,
		SingleBranch: true,
	})
	if err != nil {
		return dir, "", fmt.Errorf("%w", err)
	}

	// Get the repository's HEAD.
	head, err := repo.Head()
	if err != nil {
		return dir, "", fmt.Errorf("%w", err)
	}

	return dir, head.Hash().String(), nil
}

func loadPackages(ctx context.Context, dir, pattern string) ([]*packages.Package, error) {
	loadMode :=
		packages.NeedName |
			packages.NeedDeps |
			packages.NeedFiles |
			packages.NeedModule |
			packages.NeedTypes |
			packages.NeedImports |
			packages.NeedSyntax |
			packages.NeedTypesInfo
		// packages.NeedTypesSizes |
		// packages.NeedCompiledGoFiles |
		// packages.NeedExportFile |
		// packages.NeedEmbedPatterns

	// parseMode := parser.ParseComments
	parseMode := parser.SkipObjectResolution

	// patterns := []string{dir}
	patterns := []string{pattern}
	// patterns := []string{"all"}

	pkgs, err := packages.Load(&packages.Config{
		Mode:    loadMode,
		Context: ctx,
		Env:     os.Environ(),
		Dir:     dir,
		Tests:   false,
		ParseFile: func(fset *token.FileSet, filename string, src []byte) (*ast.File, error) {
			return parser.ParseFile(fset, filename, src, parseMode)
		},
	}, patterns...)
	if err != nil {
		return nil, err
	}

	return pkgs, nil

}

func loadSSA(ctx context.Context, pkgs []*packages.Package) (mainFn *ssa.Function, srcFns []*ssa.Function, err error) {
	ssaBuildMode := ssa.InstantiateGenerics // ssa.SanityCheckFunctions | ssa.GlobalDebug

	// Analyze the package.
	ssaProg, ssaPkgs := ssautil.Packages(pkgs, ssaBuildMode)

	// It's possible that the ssaProg is nil?
	if ssaProg == nil {
		err = fmt.Errorf("failed to create new ssa program")
		return
	}

	ssaProg.Build()

	for _, pkg := range ssaPkgs {
		if pkg == nil {
			continue
		}
		pkg.Build()
	}

	// Remove nil ssaPkgs by iterating over the slice of packages
	// and for each nil package, we append the slice up to that
	// index and then append the slice from the next index to the
	// end of the slice. This effectively removes the nil package
	// from the slice without having to allocate a new slice.
	for i := 0; i < len(ssaPkgs); i++ {
		if ssaPkgs[i] == nil {
			ssaPkgs = append(ssaPkgs[:i], ssaPkgs[i+1:]...)
			i--
		}
	}

	mainPkgs := ssautil.MainPackages(ssaPkgs)

	mainFn = mainPkgs[0].Members["main"].(*ssa.Function)

	for _, pkg := range ssaPkgs {
		for _, fn := range pkg.Members {
			if fn.Object() == nil {
				continue
			}

			if fn.Object().Name() == "_" {
				continue
			}

			pkgFn := pkg.Func(fn.Object().Name())
			if pkgFn == nil {
				continue
			}

			var addAnons func(f *ssa.Function)
			addAnons = func(f *ssa.Function) {
				srcFns = append(srcFns, f)
				for _, anon := range f.AnonFuncs {
					addAnons(anon)
				}
			}
			addAnons(pkgFn)
		}
	}

	if mainFn == nil {
		err = fmt.Errorf("failed to find main function")
		return
	}

	return
}

func loadCallGraph(ctx context.Context, mainFn *ssa.Function, srcFns []*ssa.Function) (*callgraph.Graph, error) {
	cg, err := callgraphutil.NewGraph(mainFn, srcFns...)
	if err != nil {
		return nil, fmt.Errorf("failed to create new callgraph: %w", err)
	}

	return cg, nil
}

func TestWriteDOT(t *testing.T) {
	repo, _, err := cloneGitHubRepository(context.Background(), "picatz", "taint")
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

	output := &bytes.Buffer{}

	err = callgraphutil.WriteDOT(output, cg)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(output.String())
}
