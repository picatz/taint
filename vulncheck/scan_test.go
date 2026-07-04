package vulncheck

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/picatz/taint/vulndb"
)

// loadTarget writes a single-file module to a temp directory and loads it into
// a Target. The module path is example.com/scan and its version is empty (a
// main module has no version), which the version matcher treats as "match any",
// so a fixture advisory affects it regardless of range.
func loadTarget(t *testing.T, src string) *Target {
	t.Helper()
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "go.mod"), "module example.com/scan\n\ngo 1.24.4\n")
	mustWrite(t, filepath.Join(dir, "main.go"), src)

	target, err := Load(context.Background(), LoadConfig{Dir: dir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return target
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// advisoryDB builds a fixture database with one advisory affecting
// example.com/scan, naming the given package and symbols.
func advisoryDB(t *testing.T, id, pkg string, symbols []string) vulndb.Source {
	t.Helper()
	imp := map[string]any{"path": pkg}
	if len(symbols) > 0 {
		imp["symbols"] = symbols
	}
	entry := map[string]any{
		"id": id,
		"affected": []any{map[string]any{
			"package": map[string]any{"ecosystem": "Go", "name": "example.com/scan"},
			"ranges": []any{map[string]any{
				"type":   "SEMVER",
				"events": []any{map[string]any{"introduced": "0"}},
			}},
			"ecosystem_specific": map[string]any{"imports": []any{imp}},
		}},
		"database_specific": map[string]any{"review_status": "REVIEWED"},
	}
	return jsonDB(t, map[string]any{
		"index/modules.json": []any{
			map[string]any{"path": "example.com/scan", "vulns": []any{map[string]any{"id": id}}},
		},
		"ID/" + id + ".json": entry,
	})
}

func jsonDB(t *testing.T, files map[string]any) vulndb.Source {
	t.Helper()
	fsys := fstest.MapFS{}
	for name, v := range files {
		fsys[name] = &fstest.MapFile{Data: mustJSON(t, v)}
	}
	return vulndb.NewFSSource(fsys)
}

func findingFor(res *Result, osv string) *Finding {
	for i := range res.Findings {
		if res.Findings[i].OSV == osv {
			return &res.Findings[i]
		}
	}
	return nil
}

func TestScanSymbolTier(t *testing.T) {
	// main calls the vulnerable symbol directly: reachable, but the argument is
	// a constant, so not tainted. Expect a symbol-tier finding.
	target := loadTarget(t, `package main

func vulnerable(q string) {}

func main() {
	vulnerable("constant")
}
`)
	src := advisoryDB(t, "GO-TEST-0001", "example.com/scan", []string{"vulnerable"})
	res, err := Scan(context.Background(), target, src)
	if err != nil {
		t.Fatal(err)
	}
	f := findingFor(res, "GO-TEST-0001")
	if f == nil {
		t.Fatal("expected a finding for GO-TEST-0001")
	}
	if f.Tier != TierSymbol {
		t.Fatalf("tier = %s, want symbol", f.Tier)
	}
	if f.Symbol != "vulnerable" {
		t.Fatalf("symbol = %q, want vulnerable", f.Symbol)
	}
	if len(f.Trace) == 0 {
		t.Fatal("expected a non-empty call trace")
	}
}

func TestScanTaintTier(t *testing.T) {
	// An HTTP request flows into the vulnerable symbol: taint tier.
	target := loadTarget(t, `package main

import "net/http"

func vulnerable(q string) {}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		vulnerable(r.URL.Query().Get("q"))
	})
	http.ListenAndServe(":0", nil)
}
`)
	src := advisoryDB(t, "GO-TEST-0002", "example.com/scan", []string{"vulnerable"})
	res, err := Scan(context.Background(), target, src)
	if err != nil {
		t.Fatal(err)
	}
	f := findingFor(res, "GO-TEST-0002")
	if f == nil {
		t.Fatal("expected a finding for GO-TEST-0002")
	}
	if f.Tier != TierTaint {
		t.Fatalf("tier = %s, want taint; trace=%v", f.Tier, f.Trace)
	}
	if len(f.TaintTrace) == 0 {
		t.Fatal("expected a non-empty taint trace")
	}
}

func TestScanUnreachableSymbolIsPackageTier(t *testing.T) {
	// The vulnerable symbol exists but is never called: the package is imported
	// (it is the scanned module), so the finding degrades to package tier.
	target := loadTarget(t, `package main

func vulnerable(q string) {}

func main() {}
`)
	src := advisoryDB(t, "GO-TEST-0003", "example.com/scan", []string{"vulnerable"})
	res, err := Scan(context.Background(), target, src)
	if err != nil {
		t.Fatal(err)
	}
	f := findingFor(res, "GO-TEST-0003")
	if f == nil {
		t.Fatal("expected a finding for GO-TEST-0003")
	}
	if f.Tier != TierPackage {
		t.Fatalf("tier = %s, want package", f.Tier)
	}
}

func TestScanModuleTierWildcard(t *testing.T) {
	// An advisory with no package/symbol data affecting the module: module tier.
	target := loadTarget(t, `package main

func main() {}
`)
	entry := map[string]any{
		"id": "GO-TEST-0004",
		"affected": []any{map[string]any{
			"package": map[string]any{"ecosystem": "Go", "name": "example.com/scan"},
			"ranges": []any{map[string]any{
				"type":   "SEMVER",
				"events": []any{map[string]any{"introduced": "0"}},
			}},
		}},
		"database_specific": map[string]any{"review_status": "UNREVIEWED"},
	}
	src := jsonDB(t, map[string]any{
		"index/modules.json": []any{
			map[string]any{"path": "example.com/scan", "vulns": []any{map[string]any{"id": "GO-TEST-0004"}}},
		},
		"ID/GO-TEST-0004.json": entry,
	})
	res, err := Scan(context.Background(), target, src)
	if err != nil {
		t.Fatal(err)
	}
	f := findingFor(res, "GO-TEST-0004")
	if f == nil {
		t.Fatal("expected a finding for GO-TEST-0004")
	}
	if f.Tier != TierModule {
		t.Fatalf("tier = %s, want module", f.Tier)
	}
}

func TestScanNoAdvisories(t *testing.T) {
	target := loadTarget(t, `package main

func main() {}
`)
	src := jsonDB(t, map[string]any{"index/modules.json": []any{}})
	res, err := Scan(context.Background(), target, src)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(res.Findings))
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestScanMethodReceiverSpelling(t *testing.T) {
	// The advisory names a method as "Client.Do" (no star); the code calls it
	// on a pointer, so the symbol id is "(*...Client).Do". Both receiver
	// spellings must be tried so the pointer method is matched.
	target := loadTarget(t, `package main

type Client struct{}

func (c *Client) Do(q string) {}

func main() {
	c := &Client{}
	c.Do("x")
}
`)
	src := advisoryDB(t, "GO-TEST-0005", "example.com/scan", []string{"Client.Do"})
	res, err := Scan(context.Background(), target, src)
	if err != nil {
		t.Fatal(err)
	}
	f := findingFor(res, "GO-TEST-0005")
	if f == nil {
		t.Fatal("expected a finding for the pointer-method symbol")
	}
	if f.Tier != TierSymbol {
		t.Fatalf("tier = %s, want symbol", f.Tier)
	}
}

func TestScanLibraryMode(t *testing.T) {
	// A library (no main): exported functions are entry points, so a vulnerable
	// symbol called by an exported function is reachable.
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "go.mod"), "module example.com/lib\n\ngo 1.24.4\n")
	mustWrite(t, filepath.Join(dir, "lib.go"), `package lib

func vulnerable(q string) {}

// Exported is a library entry point.
func Exported(q string) {
	vulnerable(q)
}
`)
	target, err := Load(context.Background(), LoadConfig{Dir: dir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// The advisory targets the library module itself.
	entry := map[string]any{
		"id": "GO-TEST-0006",
		"affected": []any{map[string]any{
			"package": map[string]any{"ecosystem": "Go", "name": "example.com/lib"},
			"ranges": []any{map[string]any{
				"type":   "SEMVER",
				"events": []any{map[string]any{"introduced": "0"}},
			}},
			"ecosystem_specific": map[string]any{"imports": []any{
				map[string]any{"path": "example.com/lib", "symbols": []any{"vulnerable"}},
			}},
		}},
		"database_specific": map[string]any{"review_status": "REVIEWED"},
	}
	src := jsonDB(t, map[string]any{
		"index/modules.json": []any{
			map[string]any{"path": "example.com/lib", "vulns": []any{map[string]any{"id": "GO-TEST-0006"}}},
		},
		"ID/GO-TEST-0006.json": entry,
	})
	res, err := Scan(context.Background(), target, src)
	if err != nil {
		t.Fatal(err)
	}
	f := findingFor(res, "GO-TEST-0006")
	if f == nil {
		t.Fatal("expected a finding in library mode")
	}
	if f.Tier != TierSymbol {
		t.Fatalf("tier = %s, want symbol (vulnerable is reachable via Exported)", f.Tier)
	}
}
