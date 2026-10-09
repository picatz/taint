package modelflag

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadFrom(t *testing.T) {
	dir := t.TempDir()
	const model = "package: example.com/model\nsources:\n  - call: example.com/model.Source\n"
	if err := os.WriteFile(filepath.Join(dir, "model.yaml"), []byte(model), 0600); err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"model.yaml", ".", filepath.Join(dir, "model.yaml")} {
		t.Run(path, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			var f Flag
			f.Register(fs)
			if err := fs.Parse([]string{"-models", path}); err != nil {
				t.Fatal(err)
			}
			got, err := f.LoadFrom(dir)
			if err != nil || len(got) != 1 || got[0].Package != "example.com/model" {
				t.Fatalf("models=%v err=%v", got, err)
			}
		})
	}
	var empty Flag
	if got, err := empty.LoadFrom(dir); err != nil || got != nil {
		t.Fatalf("empty models=%v err=%v", got, err)
	}
	after, err := os.Getwd()
	if err != nil || after != cwd {
		t.Fatalf("cwd changed: %q -> %q (%v)", cwd, after, err)
	}
}

func TestLoadPreservesRelativePath(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var f Flag
	f.Register(fs)
	const path = "./missing-models-for-path-test.yaml"
	if err := fs.Parse([]string{"-models", path}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Load(); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("expected original path in error, got %v", err)
	}
}
