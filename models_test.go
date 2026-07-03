package taint

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

// exampleModelsFS demonstrates the idiomatic way to ship model packs with a
// program: embed a directory of YAML and load it with LoadModels.
//
//go:embed testdata/models
var exampleModelsFS embed.FS

func TestLoadModelsFromEmbedFS(t *testing.T) {
	sub, err := fs.Sub(exampleModelsFS, "testdata/models")
	if err != nil {
		t.Fatal(err)
	}
	models, err := LoadModels(sub)
	if err != nil {
		t.Fatalf("LoadModels(embed.FS): %v", err)
	}
	if len(models) != 1 || models[0].Package != "example.com/framework" {
		t.Fatalf("unexpected embedded models: %+v", models)
	}
	// The example pack exercises every rule kind and an access-path selector.
	m := models[0]
	if len(m.Sources) != 2 || len(m.Sinks) != 1 || len(m.Sanitizers) != 1 || len(m.Summaries) != 1 {
		t.Fatalf("unexpected embedded model shape: %+v", m)
	}
	if got := selectorStrings(m.Sinks[0].Args); got != "receiver,1..2" {
		t.Fatalf("sink selectors = %q, want %q", got, "receiver,1..2")
	}
}

func selectorStrings(sels []ArgSelector) string {
	parts := make([]string, len(sels))
	for i, s := range sels {
		parts[i] = s.String()
	}
	return strings.Join(parts, ",")
}

func mustParseModels(t *testing.T, yaml string) []Model {
	t.Helper()
	models, err := ParseModels(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("ParseModels: %v", err)
	}
	return models
}

func TestParseArgSelector(t *testing.T) {
	valid := []struct {
		in           string
		wantReceiver bool
		wantLo       int
		wantHi       int
	}{
		{"0", false, 0, 0},
		{"3", false, 3, 3},
		{"0..2", false, 0, 2},
		{"1..1", false, 1, 1},
		{"receiver", true, 0, 0},
		{"Receiver", true, 0, 0},
		{"Argument[0]", false, 0, 0},
		{"Argument[1..3]", false, 1, 3},
		{"Argument[receiver]", true, 0, 0},
		// Field/element access is accepted but over-approximated to the argument.
		{"Argument[0].Field[pkg.T.f]", false, 0, 0},
		{"Argument[2].ArrayElement", false, 2, 2},
	}
	for _, tc := range valid {
		var a ArgSelector
		if err := a.parse(tc.in); err != nil {
			t.Errorf("parse(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if a.receiver != tc.wantReceiver || a.lo != tc.wantLo || a.hi != tc.wantHi {
			t.Errorf("parse(%q) = {recv:%v lo:%d hi:%d}, want {recv:%v lo:%d hi:%d}",
				tc.in, a.receiver, a.lo, a.hi, tc.wantReceiver, tc.wantLo, tc.wantHi)
		}
	}

	invalid := []string{"", "x", "-1", "2..0", "0..", "..2", "Argument[0", "Argument[]", "arg 0"}
	for _, in := range invalid {
		var a ArgSelector
		if err := a.parse(in); err == nil {
			t.Errorf("parse(%q) expected error, got none", in)
		}
	}
}

func TestArgSelectorConstructorsAndString(t *testing.T) {
	cases := map[ArgSelector]string{
		Arg(0):         "0",
		Arg(5):         "5",
		ArgRange(0, 2): "0..2",
		Receiver():     "receiver",
	}
	for sel, want := range cases {
		if sel.String() != want {
			t.Errorf("%+v.String() = %q, want %q", sel, sel.String(), want)
		}
	}
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
	if models[0].Sinks[0].Method != "(*example.com/a.DB).Exec" || len(models[0].Sinks[0].Args) != 1 || models[0].Sinks[0].Args[0].String() != "0" {
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

func TestCheckDetailedModelReceiverSink(t *testing.T) {
	cg, pkg := detailedGraphForSource(t, `package main

type Req struct{}

func userReq() *Req { return &Req{} }

func (r *Req) Exec() {}

func main() {
	r := userReq()
	r.Exec()
}
`)
	// userReq's result is the source; the sink fires when Exec is called on
	// that tainted receiver, selected via "receiver".
	model := mustParseModels(t, fmt.Sprintf(`
package: %[1]s
sources:
  - call: "%[1]s.userReq"
sinks:
  - method: "(*%[1]s.Req).Exec"
    args: [receiver]
`, pkg))
	diags := CheckDetailed(cg, NewSources(), NewSinks(), WithModels(model...))
	if len(diags) != 1 {
		t.Fatalf("expected one diagnostic from receiver sink, got %d", len(diags))
	}
}

func TestCheckDetailedModelReceiverSummary(t *testing.T) {
	cg, pkg := detailedGraphForSource(t, `package main

import "database/sql"

type Req struct{}

func userReq() *Req { return &Req{} }

// Body returns a constant, so the engine does not propagate taint on its own;
// the model's receiver->result summary is what carries it.
func (r *Req) Body() string { return "safe" }

func main() {
	db := &sql.DB{}
	r := userReq()
	db.Query(r.Body())
}
`)
	model := mustParseModels(t, fmt.Sprintf(`
package: %[1]s
sources:
  - call: "%[1]s.userReq"
summaries:
  - func: "(*%[1]s.Req).Body"
    from: [receiver]
    to: result
`, pkg))
	withModel := CheckDetailed(cg, NewSources(), NewSinks("(*database/sql.DB).Query"), WithModels(model...))
	if len(withModel) != 1 {
		t.Fatalf("expected receiver->result summary to taint the query, got %d", len(withModel))
	}
	sourceOnly := mustParseModels(t, fmt.Sprintf("package: %[1]s\nsources:\n  - call: \"%[1]s.userReq\"", pkg))
	withoutSummary := CheckDetailed(cg, NewSources(), NewSinks("(*database/sql.DB).Query"), WithModels(sourceOnly...))
	if len(withoutSummary) != 0 {
		t.Fatalf("without the summary the constant-returning Body should not taint, got %d", len(withoutSummary))
	}
}

func TestCheckDetailedModelArgRange(t *testing.T) {
	cg, pkg := detailedGraphForSource(t, `package main

import "net/http"

type DB struct{}

func (d *DB) Do(a string, b string, c string) {}

func main() {
	db := &DB{}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Tainted value in the modeled range (args 0..1).
		db.Do("x", r.URL.Query().Get("q"), "y")
	})
}
`)
	model := mustParseModels(t, fmt.Sprintf(`
package: %[1]s
sinks:
  - method: "(*%[1]s.DB).Do"
    args: ["0..1"]
`, pkg))
	diags := CheckDetailed(cg, NewSources("*net/http.Request"), NewSinks(), WithModels(model...))
	if len(diags) != 1 {
		t.Fatalf("expected one diagnostic from arg range 0..1, got %d", len(diags))
	}

	// The same tainted value at position 2 is outside the modeled range.
	cgOut, _ := detailedGraphForSource(t, `package main

import "net/http"

type DB struct{}

func (d *DB) Do(a string, b string, c string) {}

func main() {
	db := &DB{}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		db.Do("x", "y", r.URL.Query().Get("q"))
	})
}
`)
	out := CheckDetailed(cgOut, NewSources("*net/http.Request"), NewSinks(), WithModels(model...))
	if len(out) != 0 {
		t.Fatalf("expected no diagnostic when the taint is outside the range, got %d", len(out))
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
