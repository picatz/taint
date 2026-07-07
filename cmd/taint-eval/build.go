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
}

// buildBinaries compiles the six per-package analyzer binaries and the taint
// binary into a directory inside the cache and returns lookups for RunTarget.
// Building once per harness invocation avoids re-compiling for each target;
// an already-built binary is reused, so clear the cache bin directory to pick
// up source changes.
func buildBinaries(ctx context.Context, cacheDir CacheDir, repoRoot string) (binaries, error) {
	binDir := filepath.Join(string(cacheDir), "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return binaries{}, err
	}
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
		if _, err := os.Stat(bin); err == nil {
			continue
		}
		cmd := exec.CommandContext(ctx, "go", "build", "-o", bin, pkg)
		cmd.Dir = repoRoot
		cmd.Env = os.Environ()
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return binaries{}, fmt.Errorf("go build %s: %w", pkg, err)
		}
	}
	return binaries{
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
