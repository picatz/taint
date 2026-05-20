package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// buildAnalyzerBinaries compiles cmd/sqli, cmd/logi, cmd/cmdi, and cmd/xss into a
// temporary directory inside the cache and returns a lookup function for use
// by RunTarget. Building once per harness invocation avoids the cost of
// re-compiling for each target.
func buildAnalyzerBinaries(ctx context.Context, cacheDir CacheDir, repoRoot string) (analyzerCommand, error) {
	binDir := filepath.Join(string(cacheDir), "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return nil, err
	}
	binaries := map[string]string{
		"sqli": "github.com/picatz/taint/cmd/sqli",
		"logi": "github.com/picatz/taint/cmd/logi",
		"cmdi": "github.com/picatz/taint/cmd/cmdi",
		"xss":  "github.com/picatz/taint/cmd/xss",
	}
	paths := map[string]string{}
	for name, pkg := range binaries {
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
			return nil, fmt.Errorf("go build %s: %w", pkg, err)
		}
	}
	return func(name string) (string, error) {
		if bin, ok := paths[name]; ok {
			return bin, nil
		}
		return "", fmt.Errorf("unknown analyzer %q", name)
	}, nil
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}
