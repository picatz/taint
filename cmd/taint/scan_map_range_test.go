package main

import (
	"bytes"
	"context"
	"reflect"
	"testing"
)

// Synthetic HTTP-to-SQL flows exercise the public scanner with both occurrence
// scopes. Only static analysis runs; the fixture never starts an HTTP server.
func TestScanMapRangeComponents(t *testing.T) {
	t.Setenv("GOWORK", "off")
	dir := scanModelFiles(t, map[string]string{
		"go.mod": "module example.com/maprange\ngo 1.26.0\n",
		"main.go": `package main

import (
	"database/sql"
	"net/http"
)

func direct(db *sql.DB, r *http.Request) {
	db.Query(r.FormValue("q")) // true positive: direct control
}
func lookup(db *sql.DB, r *http.Request) {
	m := map[string]string{"q": r.FormValue("q")}
	db.Query(m["q"]) // true positive: lookup control
}
func mapValue(db *sql.DB, r *http.Request) {
	m := map[string]string{"q": r.FormValue("q")}
	for _, v := range m {
		db.Query(v) // true positive: map value
	}
}
func mapKey(db *sql.DB, r *http.Request) {
	m := map[string]string{r.FormValue("q"): "safe"}
	for k := range m {
		db.Query(k) // true positive: map key
	}
}
func safeValue(db *sql.DB, r *http.Request) {
	m := map[string]string{r.FormValue("q"): "safe"}
	for _, v := range m {
		db.Query(v) // clean: tainted key does not taint value
	}
}
func main() {
	db := &sql.DB{}
	http.HandleFunc("/direct", func(w http.ResponseWriter, r *http.Request) { direct(db, r) })
	http.HandleFunc("/lookup", func(w http.ResponseWriter, r *http.Request) { lookup(db, r) })
	http.HandleFunc("/value", func(w http.ResponseWriter, r *http.Request) { mapValue(db, r) })
	http.HandleFunc("/key", func(w http.ResponseWriter, r *http.Request) { mapKey(db, r) })
	http.HandleFunc("/safe", func(w http.ResponseWriter, r *http.Request) { safeValue(db, r) })
}
`,
	})
	for _, scope := range []string{"legacy", "selected"} {
		t.Run(scope, func(t *testing.T) {
			var out, stderr bytes.Buffer
			code := runScan(context.Background(), []string{"-C", dir, "-analyzers=sqli", "-scope=" + scope, "-format=json", "./..."}, &out, &stderr)
			if code != scanExitFindings {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, &out, &stderr)
			}
			got := scanModelJSON(t, out.String())
			var lines []int
			for _, finding := range got {
				if finding.Analyzer != "sqli" || finding.File != "main.go" {
					t.Fatalf("wrong attribution: %+v", finding)
				}
				lines = append(lines, finding.Line)
			}
			if !reflect.DeepEqual(lines, []int{9, 13, 18, 24}) {
				t.Fatalf("lines=%v want [9 13 18 24]", lines)
			}
		})
	}
}
