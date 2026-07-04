package vulncheck

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/picatz/taint/vulndb"
)

// TestScanRealDatabase scans a module that funnels an HTTP request into
// golang.org/x/text/language.Parse at a version affected by GO-2021-0113,
// against the live Go vulnerability database, and asserts the finding surfaces
// at taint tier. It is opt-in (network + module download) and runs only when
// TAINT_VULN_NETWORK is set, so the default suite stays hermetic.
func TestScanRealDatabase(t *testing.T) {
	if os.Getenv("TAINT_VULN_NETWORK") == "" {
		t.Skip("set TAINT_VULN_NETWORK=1 to run the live-database integration test")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/realvuln\n\ngo 1.24.4\n\nrequire golang.org/x/text v0.3.0\n")
	writeFile(t, filepath.Join(dir, "main.go"), `package main

import (
	"fmt"
	"net/http"

	"golang.org/x/text/language"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tag, _ := language.Parse(r.URL.Query().Get("lang"))
		fmt.Fprintln(w, tag)
	})
	http.ListenAndServe(":8080", nil)
}
`)
	runGo(t, dir, "mod", "tidy")

	src, err := vulndb.NewHTTPSource(vulndb.DefaultBaseURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	target, err := Load(context.Background(), LoadConfig{Dir: dir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	res, err := Scan(context.Background(), target, src)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	f := findingFor(res, "GO-2021-0113")
	if f == nil {
		t.Fatalf("expected GO-2021-0113; got findings %+v", res.Findings)
	}
	if f.Tier != TierTaint {
		t.Fatalf("GO-2021-0113 tier = %s, want taint (request flows into language.Parse)", f.Tier)
	}
	if f.FixedVersion == "" {
		t.Error("expected a fixed version to be reported")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func runGo(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go %v: %v\n%s", args, err, out)
	}
}
