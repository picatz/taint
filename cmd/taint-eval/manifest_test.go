package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadManifest_ValidatesAndSorts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yaml")
	body := `targets:
  - name: a
    kind: local
    path: ./a
    analyzers: [xss, sqli]
    expect:
      - analyzer: sqli
        file: db.go
        line: 7
        note: known sink
  - name: b
    kind: git
    repo: https://example.com/o/r.git
    commit: deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
    analyzers: [logi]
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if got := m.Targets[0].Analyzers; got[0] != "sqli" || got[1] != "xss" {
		t.Fatalf("expected analyzers sorted alphabetically, got %v", got)
	}
	if got := m.Targets[0].Expect; len(got) != 1 || got[0] != (ExpectedFinding{Analyzer: "sqli", File: "db.go", Line: 7, Note: "known sink"}) {
		t.Fatalf("expected ground-truth entry parsed, got %+v", got)
	}
	if got := m.Targets[0].Packages; len(got) != 1 || got[0] != "./..." {
		t.Fatalf("expected default packages [\"./...\"], got %v", got)
	}
	if m.FindTarget("b") == nil {
		t.Fatal("expected to find target b")
	}
	if m.FindTarget("missing") != nil {
		t.Fatal("did not expect to find target missing")
	}
}

func TestLoadManifest_RejectsInvalid(t *testing.T) {
	cases := map[string]string{
		"missing name": `targets:
  - kind: local
    path: ./a
    analyzers: [sqli]
`,
		"local without path": `targets:
  - name: a
    kind: local
    analyzers: [sqli]
`,
		"git without commit": `targets:
  - name: a
    kind: git
    repo: https://example.com/o/r.git
    analyzers: [sqli]
`,
		"duplicate name": `targets:
  - name: a
    kind: local
    path: ./a
    analyzers: [sqli]
  - name: a
    kind: local
    path: ./b
    analyzers: [logi]
`,
		"unknown kind": `targets:
  - name: a
    kind: unknown
    path: ./a
    analyzers: [sqli]
`,
		"no analyzers": `targets:
  - name: a
    kind: local
    path: ./a
    analyzers: []
`,
		"expect without analyzer": `targets:
  - name: a
    kind: local
    path: ./a
    analyzers: [sqli]
    expect:
      - file: main.go
`,
		"expect analyzer not configured": `targets:
  - name: a
    kind: local
    path: ./a
    analyzers: [sqli]
    expect:
      - analyzer: cmdi
        file: main.go
`,
		"expect without file": `targets:
  - name: a
    kind: local
    path: ./a
    analyzers: [sqli]
    expect:
      - analyzer: sqli
        line: 3
`,
		"expect negative line": `targets:
  - name: a
    kind: local
    path: ./a
    analyzers: [sqli]
    expect:
      - analyzer: sqli
        file: main.go
        line: -1
`,
	}
	for label, body := range cases {
		t.Run(label, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "targets.yaml")
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadManifest(path); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestSelectTargets(t *testing.T) {
	m := &Manifest{Targets: []Target{
		{Name: "local-a", Kind: KindLocal, Path: "./a", Analyzers: []string{"sqli"}},
		{Name: "git-b", Kind: KindGit, Repo: "u", Commit: "c", Analyzers: []string{"sqli"}},
	}}
	all, err := m.SelectTargets("")
	if err != nil || len(all) != 2 {
		t.Fatalf("expected 2 targets, got %d err=%v", len(all), err)
	}
	locals, err := m.SelectTargets("local")
	if err != nil || len(locals) != 1 || locals[0].Name != "local-a" {
		t.Fatalf("local filter returned %v err=%v", locals, err)
	}
	gits, err := m.SelectTargets("git")
	if err != nil || len(gits) != 1 || gits[0].Name != "git-b" {
		t.Fatalf("git filter returned %v err=%v", gits, err)
	}
	named, err := m.SelectTargets("git-b")
	if err != nil || len(named) != 1 || named[0].Name != "git-b" {
		t.Fatalf("named filter returned %v err=%v", named, err)
	}
	if _, err := m.SelectTargets("unknown"); err == nil {
		t.Fatal("expected error for unknown selector")
	}
}

func TestResolveLocalPath(t *testing.T) {
	got := ResolveLocalPath("/manifest", "fixtures/a")
	want := filepath.Clean("/manifest/fixtures/a")
	if got != want {
		t.Fatalf("ResolveLocalPath relative: got %q want %q", got, want)
	}
	if got := ResolveLocalPath("/manifest", "/abs/path"); got != "/abs/path" {
		t.Fatalf("ResolveLocalPath absolute: got %q", got)
	}
}
