package taint

import (
	"testing"

	"github.com/picatz/taint/callgraphutil"
	"golang.org/x/tools/go/callgraph"
)

func TestShellCommandFlagRecognition(t *testing.T) {
	tests := []struct {
		name  string
		shell string
		flag  string
		want  bool
	}{
		{name: "sh c", shell: "sh", flag: "-c", want: true},
		{name: "bash login command", shell: "bash", flag: "-lc", want: true},
		{name: "sh errexit command", shell: "/bin/sh", flag: "-ec", want: true},
		{name: "dash nounset command", shell: "dash", flag: "-uc", want: true},
		{name: "zsh login command", shell: "zsh", flag: "-lc", want: true},
		{name: "ksh command", shell: "ksh", flag: "-c", want: true},
		{name: "ash command", shell: "ash", flag: "-c", want: true},
		{name: "unknown shell", shell: "grep", flag: "-c", want: false},
		{name: "posix long flag", shell: "sh", flag: "--command", want: false},
		{name: "posix malformed command", shell: "sh", flag: "-cecho", want: false},
		{name: "posix non command", shell: "sh", flag: "-x", want: false},
		{name: "cmd c", shell: "cmd.exe", flag: "/c", want: true},
		{name: "cmd uppercase c", shell: "cmd", flag: "/C", want: true},
		{name: "powershell command", shell: "powershell", flag: "-Command", want: true},
		{name: "pwsh c", shell: "pwsh", flag: "-c", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isShellCommandFlag(tt.shell, tt.flag); got != tt.want {
				t.Fatalf("isShellCommandFlag(%q, %q) = %v, want %v", tt.shell, tt.flag, got, tt.want)
			}
		})
	}
}

func TestCheckDetailedExecCommandReportsConstantShellAlias(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "os/exec"

func source() string { return "user" }

func main() {
	var shell string
	shell = "sh"
	exec.Command(shell, "-c", source())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("os/exec.Command"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected one diagnostic through constant shell alias, got %d", len(diagnostics))
	}
}

func TestExecCommandSinkArgumentsSelectShellCommandFromVariadicSlice(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "os/exec"

func source() string { return "user" }

func main() {
	args := []string{"-c", source()}
	exec.Command("sh", args...)
}
`)

	path := singleSinkPath(t, cg, "os/exec.Command")
	selected := execCommandSinkArguments(path.Last())
	if len(selected) != 2 {
		t.Fatalf("expected executable and shell command arguments, got %d", len(selected))
	}
	tainted, src, _ := checkSSAValue(path, NewSources(pkgPath+".source"), selected[1], valueSet{})
	if !tainted || src != pkgPath+".source" {
		t.Fatalf("expected selected shell command argument to be tainted by %q, got tainted=%v source=%q", pkgPath+".source", tainted, src)
	}
}

func TestCheckDetailedExecCommandIgnoresOrdinaryVariadicArgs(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "os/exec"

func source() string { return "user" }

func main() {
	args := []string{source()}
	exec.Command("grep", args...)
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("os/exec.Command"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected ordinary variadic process arguments to stay clean, got %d diagnostics", len(diagnostics))
	}
}

func FuzzShellCommandFlagRecognition(f *testing.F) {
	for _, seed := range []struct {
		shell string
		flag  string
	}{
		{shell: "sh", flag: "-c"},
		{shell: "bash", flag: "-lc"},
		{shell: "sh", flag: "-ec"},
		{shell: "cmd.exe", flag: "/c"},
		{shell: "powershell", flag: "-Command"},
		{shell: "", flag: ""},
	} {
		f.Add(seed.shell, seed.flag)
	}

	f.Fuzz(func(t *testing.T, shell, flag string) {
		t.Helper()
		_ = isShellCommandFlag(shell, flag)
	})
}

func singleSinkPath(t *testing.T, cg *callgraph.Graph, sink string) callgraphutil.Path {
	t.Helper()
	paths := findAllSinkCallSitePaths(cg, exactSinkRule(sink))
	if len(paths) != 1 {
		t.Fatalf("expected one path to %s, got %d", sink, len(paths))
	}
	return paths[0]
}
