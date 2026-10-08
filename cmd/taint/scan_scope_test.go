package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanScopeValidationBeforeLoad(t *testing.T) {
	var out, stderr bytes.Buffer
	code := runScan(context.Background(), []string{"-scope=all", "-C=/does/not/exist"}, &out, &stderr)
	if code != scanExitError || out.Len() != 0 || !strings.Contains(stderr.String(), "unknown -scope") || strings.Contains(stderr.String(), "loading packages") {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, &out, &stderr)
	}
}

func TestScanSelectedProfile(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.com/scanselected\ngo 1.26.0\n",
		"library.go": `package selected
 import ("database/sql"; "net/http")
 var db *sql.DB
 var request *http.Request
 func init() { db.Query(request.URL.Query().Get("init")) }
 func Handler(r *http.Request) { db.Query(r.URL.Query().Get("q")) }
 func Safe(r *http.Request) { db.Query("SELECT $1", r.URL.Query().Get("q")) }
 `,
	}
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOWORK", "off")
	for _, format := range []string{"json", "sarif", "text"} {
		t.Run(format, func(t *testing.T) {
			args := []string{"-C", dir, "-scope=selected", "-analyzers=sqli", "-format=" + format}
			var out, stderr bytes.Buffer
			code := runScan(context.Background(), args, &out, &stderr)
			if code != scanExitFindings {
				t.Fatalf("code=%d out=%s stderr=%s", code, &out, &stderr)
			}
			if strings.Contains(out.String(), "scope=") || strings.Contains(stderr.String(), "scope=") {
				t.Fatal("unsolicited profile diagnostics")
			}
			if format != "text" && !json.Valid(out.Bytes()) {
				t.Fatalf("invalid JSON: %s", &out)
			}
			var covered, explanation bytes.Buffer
			code2 := runScan(context.Background(), append(args, "-coverage"), &covered, &explanation)
			if code2 != code || out.String() != covered.String() || !strings.Contains(explanation.String(), "scope=selected;") {
				t.Fatalf("coverage changed report: %d/%d\n%s\n%s\n%s", code, code2, &out, &covered, &explanation)
			}
		})
	}
	var implicit, explicit, aerr, berr bytes.Buffer
	a := runScan(context.Background(), []string{"-C", dir, "-analyzers=sqli", "-format=json"}, &implicit, &aerr)
	b := runScan(context.Background(), []string{"-C", dir, "-analyzers=sqli", "-format=json", "-scope=legacy"}, &explicit, &berr)
	if a != b || implicit.String() != explicit.String() || aerr.String() != berr.String() {
		t.Fatal("explicit legacy differs from default")
	}
}
