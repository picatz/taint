package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// binaries holds the compiled tools RunTarget needs: the per-package analyzer
// lookup for the standard path, and the taint binary (whose "scan" subcommand
// is the whole-program scanner) for whole-program targets.
type binaries struct {
	analyzer analyzerCommand
	taint    string
	cleanup  func()
}

// buildBinaries compiles all tools from repoRoot once per invocation. Go's
// build cache reuses unchanged compilation work; executables must not be
// reused across invocations because the source or build environment can change.
// Each invocation owns its directory, so overlapping runs cannot replace one
// another's binaries. The caller must defer cleanup after a successful build.
func buildBinaries(ctx context.Context, cacheDir CacheDir, repoRoot string) (binaries, error) {
	binDir, err := os.MkdirTemp(string(cacheDir), "bin-")
	if err != nil {
		return binaries{}, err
	}
	cleanup := func() { _ = os.RemoveAll(binDir) }
	built := false
	defer func() {
		if !built {
			cleanup()
		}
	}()
	pkgs := map[string]string{
		"sqli":  "github.com/picatz/taint/cmd/sqli",
		"logi":  "github.com/picatz/taint/cmd/logi",
		"cmdi":  "github.com/picatz/taint/cmd/cmdi",
		"xss":   "github.com/picatz/taint/cmd/xss",
		"ptrv":  "github.com/picatz/taint/cmd/ptrv",
		"ssrf":  "github.com/picatz/taint/cmd/ssrf",
		"taint": "github.com/picatz/taint/cmd/taint",
	}
	paths := map[string]string{}
	for name, pkg := range pkgs {
		bin := filepath.Join(binDir, name+exeSuffix())
		paths[name] = bin
		cmd := exec.CommandContext(ctx, "go", "build", "-o", bin, pkg)
		cmd.Dir = repoRoot
		cmd.Env = os.Environ()
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return binaries{}, fmt.Errorf("go build %s: %w", pkg, err)
		}
	}
	built = true
	return binaries{
		cleanup: cleanup,
		analyzer: func(name string) (string, error) {
			if bin, ok := paths[name]; ok && name != "taint" {
				return bin, nil
			}
			return "", fmt.Errorf("unknown analyzer %q", name)
		},
		taint: paths["taint"],
	}, nil
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}
