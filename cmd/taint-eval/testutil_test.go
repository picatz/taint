package main

import (
	"os/exec"
	"testing"
)

// goCmd resolves the local "go" binary. Tests fail loudly if it is missing
// because they cannot build the fake analyzers without it.
func goCmd(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	bin, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("go binary not on PATH: %v", err)
	}
	return exec.Command(bin, args...)
}
