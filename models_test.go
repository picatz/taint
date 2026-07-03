package taint

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func mustParseModels(t *testing.T, yaml string) []Model {
	t.Helper()
	models, err := ParseModels(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("ParseModels: %v", err)
	}
	return models
}

func TestModelsFromPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "one.yaml"), []byte("package: example.com/a\nsinks:\n  - {method: p.A}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "two.yml"), []byte("package: example.com/b"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Directory: loads every YAML file.
	dirModels, err := ModelsFromPath(dir)
	if err != nil {
		t.Fatalf("ModelsFromPath(dir): %v", err)
	}
	if len(dirModels) != 2 {
		t.Fatalf("expected 2 models from directory, got %d", len(dirModels))
	}

	// Single file: loads just that file.
	fileModels, err := ModelsFromPath(filepath.Join(dir, "one.yaml"))
	if err != nil {
		t.Fatalf("ModelsFromPath(file): %v", err)
	}
	if len(fileModels) != 1 || fileModels[0].Package != "example.com/a" {
		t.Fatalf("unexpected file models: %+v", fileModels)
	}

	// Empty path is a no-op.
	if ms, err := ModelsFromPath(""); err != nil || ms != nil {
		t.Fatalf("ModelsFromPath(\"\") = %v, %v; want nil, nil", ms, err)
	}

	if got := ModelPackages(dirModels); len(got) != 2 || got[0] != "example.com/a" || got[1] != "example.com/b" {
		t.Fatalf("ModelPackages = %v", got)
	}
}

func TestParseModelsMultiDocument(t *testing.T) {
	models := mustParseModels(t, `
package: example.com/a
sinks:
  - method: "(*example.com/a.DB).Exec"
    args: [0]
    kind: sql-injection
sources:
  - type: "*example.com/a.Request"
---
package: example.com/b
sanitizers:
  - func: example.com/b.Escape
summaries:
  - func: example.com/b.Concat
    from: [0, 1]
    to: return
`)
	if len(models) != 2 {
		t.Fatalf("expected 2 models, got %d", len(models))
	}
	if models[0].Package != "example.com/a" || len(models[0].Sinks) != 1 {
		t.Fatalf("unexpected first model: %+v", models[0])
	}
	if models[0].Sinks[0].Method != "(*example.com/a.DB).Exec" || len(models[0].Sinks[0].Args) != 1 || models[0].Sinks[0].Args[0] != 0 {
		t.Fatalf("unexpected sink: %+v", models[0].Sinks[0])
	}
	if len(models[1].Summaries) != 1 || models[1].Summaries[0].To != "return" {
		t.Fatalf("unexpected second model: %+v", models[1])
	}
}

func TestParseModelsSkipsBlankDocuments(t *testing.T) {
	models := mustParseModels(t, "---\npackage: example.com/a\n---\n")
	if len(models) != 1 {
		t.Fatalf("expected 1 model, got %d", len(models))
	}
}

func TestParseModelsValidation(t *testing.T) {
	cases := map[string]string{
		"missing package": `sinks: [{method: "pkg.Sink"}]`,
		"missing method":  "package: p\nsinks:\n  - args: [0]",
		"source needs exactly one": `
package: p
sources:
  - type: "*p.T"
    call: p.F`,
		"source needs at least one": "package: p\nsources:\n  - kind: remote",
		"missing sanitizer func":    "package: p\nsanitizers:\n  - kind: x",
		"missing summary func":      "package: p\nsummaries:\n  - from: [0]",
		"unsupported to":            "package: p\nsummaries:\n  - {func: p.F, to: argument}",
		"negative sink arg":         "package: p\nsinks:\n  - {method: p.S, args: [-1]}",
		"negative summary from":     "package: p\nsummaries:\n  - {func: p.F, from: [-2]}",
	}
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseModels(strings.NewReader(yaml)); err == nil {
				t.Fatalf("expected validation error for %q", name)
			}
		})
	}
}

func TestLoadModelsFromFS(t *testing.T) {
	fsys := fstest.MapFS{
		"b.yaml":       {Data: []byte("package: example.com/b\nsinks:\n  - {method: p.B}")},
		"a.yaml":       {Data: []byte("package: example.com/a\nsinks:\n  - {method: p.A}")},
		"notes.txt":    {Data: []byte("ignored")},
		"nested/c.yml": {Data: []byte("package: example.com/c")},
	}
	models, err := LoadModels(fsys)
	if err != nil {
		t.Fatalf("LoadModels: %v", err)
	}
	// Only top-level *.yaml/*.yml, sorted by path: a.yaml then b.yaml.
	if len(models) != 2 || models[0].Package != "example.com/a" || models[1].Package != "example.com/b" {
		t.Fatalf("unexpected models: %+v", models)
	}
}

func TestCheckDetailedModelSink(t *testing.T) {
	cg, pkg := detailedGraphForSource(t, `package main

import "net/http"

type DB struct{}

func (d *DB) Exec(query string) {}

func main() {
	db := &DB{}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		db.Exec(r.URL.Query().Get("q"))
	})
}
`)
	model := mustParseModels(t, fmt.Sprintf(`
package: %[1]s
sinks:
  - method: "(*%[1]s.DB).Exec"
    args: [0]
    kind: sql-injection
`, pkg))
	diags := CheckDetailed(cg, NewSources("*net/http.Request"), NewSinks(), WithModels(model...))
	if len(diags) != 1 {
		t.Fatalf("expected one diagnostic from model sink, got %d", len(diags))
	}
}

func TestCheckDetailedModelSinkArgPrecision(t *testing.T) {
	cg, pkg := detailedGraphForSource(t, `package main

import "net/http"

type DB struct{}

func (d *DB) Query(query string, arg string) {}

func main() {
	db := &DB{}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Only the second parameter is user-controlled; the query text is
		// constant. A model that marks only arg 0 as the channel must stay
		// clean.
		db.Query("SELECT 1", r.URL.Query().Get("q"))
	})
}
`)
	model := mustParseModels(t, fmt.Sprintf(`
package: %[1]s
sinks:
  - method: "(*%[1]s.DB).Query"
    args: [0]
`, pkg))
	diags := CheckDetailed(cg, NewSources("*net/http.Request"), NewSinks(), WithModels(model...))
	if len(diags) != 0 {
		t.Fatalf("expected no diagnostic (tainted arg is not the modeled channel), got %d", len(diags))
	}
}

func TestCheckDetailedModelSource(t *testing.T) {
	cg, pkg := detailedGraphForSource(t, `package main

import "database/sql"

type Request struct{ Body string }

func handler(req *Request) {
	db := &sql.DB{}
	db.Query(req.Body)
}

func main() {
	handler(&Request{})
}
`)
	model := mustParseModels(t, fmt.Sprintf(`
package: %[1]s
sources:
  - type: "*%[1]s.Request"
`, pkg))
	diags := CheckDetailed(cg, NewSources(), NewSinks("(*database/sql.DB).Query"), WithModels(model...))
	if len(diags) != 1 {
		t.Fatalf("expected one diagnostic from model source, got %d", len(diags))
	}
}

func TestCheckDetailedModelSanitizer(t *testing.T) {
	cg, pkg := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"net/http"
)

func clean(s string) string { return s }

func main() {
	db := &sql.DB{}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		db.Query(clean(r.URL.Query().Get("q")))
	})
}
`)
	model := mustParseModels(t, fmt.Sprintf(`
package: %[1]s
sanitizers:
  - func: %[1]s.clean
`, pkg))
	withModel := CheckDetailed(cg, NewSources("*net/http.Request"), NewSinks("(*database/sql.DB).Query"), WithModels(model...))
	if len(withModel) != 0 {
		t.Fatalf("expected model sanitizer to clear the finding, got %d", len(withModel))
	}
	// Without the model the flow is reported.
	withoutModel := CheckDetailed(cg, NewSources("*net/http.Request"), NewSinks("(*database/sql.DB).Query"))
	if len(withoutModel) != 1 {
		t.Fatalf("expected one diagnostic without the sanitizer model, got %d", len(withoutModel))
	}
}

func TestCheckDetailedModelSummary(t *testing.T) {
	cg, pkg := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"net/http"
)

func wrap(a string, b string) string { return a }

func main() {
	db := &sql.DB{}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		db.Query(wrap("x", r.URL.Query().Get("q")))
	})
}
`)
	model := mustParseModels(t, fmt.Sprintf(`
package: %[1]s
summaries:
  - func: %[1]s.wrap
    from: [0, 1]
    to: return
`, pkg))
	diags := CheckDetailed(cg, NewSources("*net/http.Request"), NewSinks("(*database/sql.DB).Query"), WithModels(model...))
	if len(diags) != 1 {
		t.Fatalf("expected model summary to propagate taint through wrap, got %d", len(diags))
	}
}
