package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeAnalyzerBin builds a tiny Go program that prints fixed JSON to stdout,
// allowing the runner to be tested without invoking the real analyzers.
func fakeAnalyzerBin(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	prog := `package main
import (
	"fmt"
)
func main() {
	fmt.Print(` + "`" + body + "`" + `)
}
`
	if err := os.WriteFile(src, []byte(prog), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, name+exeSuffix())
	cmd := goCmd(t, "build", "-o", out, src)
	cmd.Dir = dir
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build fake analyzer: %v\n%s", err, string(b))
	}
	return out
}

func TestRunTarget_FakeBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("path layout differs on windows")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	body := `{"pkg/x":{"sqli":[{"posn":"` + root + `/main.go:7:11","message":"potential sql injection"}]}}`
	bin := fakeAnalyzerBin(t, "sqli", body)

	target := Target{
		Name:      "fake",
		Kind:      KindLocal,
		Path:      root,
		Packages:  []string{"./..."},
		Analyzers: []string{"sqli"},
	}
	cmdFor := func(name string) (string, error) {
		if name != "sqli" {
			t.Fatalf("unexpected analyzer: %s", name)
		}
		return bin, nil
	}
	snap, err := RunTarget(context.Background(), target, root, cmdFor)
	if err != nil {
		t.Fatalf("RunTarget: %v", err)
	}
	res := snap.Analyzers["sqli"]
	if res.Count != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", res.Count, res.Findings)
	}
	if res.Findings[0].File != "main.go" {
		t.Fatalf("expected normalized file path main.go, got %q", res.Findings[0].File)
	}
}

func TestRunTarget_DiagnosticsOutsideRootAreDropped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("path layout differs on windows")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	body := `{"pkg/x":{"sqli":[{"posn":"/elsewhere/main.go:1:1","message":"ignored"}]}}`
	bin := fakeAnalyzerBin(t, "sqli", body)
	target := Target{
		Name: "fake", Kind: KindLocal, Path: root,
		Packages: []string{"./..."}, Analyzers: []string{"sqli"},
	}
	snap, err := RunTarget(context.Background(), target, root, func(string) (string, error) { return bin, nil })
	if err != nil {
		t.Fatal(err)
	}
	if snap.Analyzers["sqli"].Count != 0 {
		t.Fatalf("expected outside-root diagnostic to be dropped, got %+v", snap.Analyzers["sqli"])
	}
}

func TestRunTarget_StderrNoiseTolerated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("path layout differs on windows")
	}
	root := t.TempDir()
	bin := fakeAnalyzerWithStderr(t, "logi", `{"p":{"logi":[]}}`, "logi: flag noise on stderr\n")
	target := Target{
		Name: "fake", Kind: KindLocal, Path: root,
		Packages: []string{"./..."}, Analyzers: []string{"logi"},
	}
	snap, err := RunTarget(context.Background(), target, root, func(string) (string, error) { return bin, nil })
	if err != nil {
		t.Fatalf("RunTarget: %v", err)
	}
	if snap.Analyzers["logi"].Count != 0 {
		t.Fatalf("expected zero findings, got %+v", snap.Analyzers["logi"])
	}
}

// fakeAnalyzerWithStderr builds a binary that prints body to stdout and noise
// to stderr, mirroring the singlechecker informational messages.
func fakeAnalyzerWithStderr(t *testing.T, name, body, stderrNoise string) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	bodyEsc := strings.ReplaceAll(body, "`", "")
	noiseEsc := strings.ReplaceAll(stderrNoise, "`", "")
	prog := `package main
import (
	"fmt"
	"os"
)
func main() {
	fmt.Fprint(os.Stderr, ` + "`" + noiseEsc + "`" + `)
	fmt.Print(` + "`" + bodyEsc + "`" + `)
}
`
	if err := os.WriteFile(src, []byte(prog), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, name+exeSuffix())
	cmd := goCmd(t, "build", "-o", out, src)
	cmd.Dir = dir
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, string(b))
	}
	return out
}
