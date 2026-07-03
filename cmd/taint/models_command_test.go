package main

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runModelsCommand(t *testing.T, args ...string) string {
	t.Helper()
	var buf bytes.Buffer
	bt := bufio.NewWriter(&buf)
	if err := builtinCommandModels.fn(context.Background(), bt, args, nil); err != nil {
		t.Fatalf("models command: %v", err)
	}
	bt.Flush()
	return buf.String()
}

func TestModelsCommand(t *testing.T) {
	t.Cleanup(func() { loadedModels = nil })

	dir := t.TempDir()
	path := filepath.Join(dir, "m.yaml")
	if err := os.WriteFile(path, []byte(`package: example.com/acme
sources:
  - call: example.com/acme.UserInput
sinks:
  - method: "(*example.com/acme.DB).Exec"
    args: [receiver, "1..2"]
    kind: sql-injection
summaries:
  - func: example.com/acme.Concat
    from: [0]
`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Loading reports success and stores the models.
	out := runModelsCommand(t, path)
	if !strings.Contains(out, "loaded 1 model(s)") {
		t.Fatalf("expected load confirmation, got:\n%s", out)
	}
	if len(loadedModels) != 1 {
		t.Fatalf("expected 1 loaded model, got %d", len(loadedModels))
	}

	// The rendered summary reflects the parsed rules, including selectors.
	for _, want := range []string{
		"package example.com/acme",
		"(*example.com/acme.DB).Exec",
		"args=[receiver,1..2]",
		"kind=sql-injection",
		"call example.com/acme.UserInput",
		"example.com/acme.Concat",
		"from=[0]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q in:\n%s", want, out)
		}
	}

	// With no argument the currently-loaded models are shown.
	if out := runModelsCommand(t); !strings.Contains(out, "package example.com/acme") {
		t.Fatalf("expected loaded models to be shown, got:\n%s", out)
	}

	// A bad path reports an error and leaves the loaded models intact.
	if out := runModelsCommand(t, filepath.Join(dir, "missing.yaml")); !strings.Contains(out, "✗") {
		t.Fatalf("expected an error for a missing path, got:\n%s", out)
	}
	if len(loadedModels) != 1 {
		t.Fatalf("failed load should not clear existing models, have %d", len(loadedModels))
	}
}
