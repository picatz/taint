package wholeprogram_test

import (
	"context"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/picatz/taint"
	cmdi "github.com/picatz/taint/command/injection"
	ptrv "github.com/picatz/taint/command/pathtraversal"
	"github.com/picatz/taint/internal/wholeprogram"
	logi "github.com/picatz/taint/log/injection"
	"github.com/picatz/taint/network/ssrf"
	sqli "github.com/picatz/taint/sql/injection"
	"github.com/picatz/taint/xss"
	"golang.org/x/tools/go/callgraph"
)

// Exercise the public detector seam with real external model declarations and
// selected source occurrences. Every detector has a positive control, so an
// accidentally dropped model or an ignored option cannot pass vacuously.
func TestDetectorCheckWithOptions(t *testing.T) {
	const source = `package handlers
import (
 "bytes"
 "context"
 "database/sql"
 "fmt"
 "html"
 "log"
 "net/http"
 "os"
 "os/exec"
)
func Command(r *http.Request) {
 exec.Command(r.FormValue("command")) // finding:cmdi
 exec.Command("echo", r.FormValue("argument")) // safe:cmdi
}
func Logging(r *http.Request) {
 log.Print(r.FormValue("message")) // finding:logi
}
func Path(r *http.Request) {
 os.Open(r.FormValue("path")) // finding:ptrv
 os.WriteFile("fixed.txt", []byte(r.FormValue("contents")), 0600) // safe:ptrv
}
func SQL(r *http.Request, db *sql.DB) {
 db.Query(r.FormValue("query")) // finding:sqli
 db.Query("SELECT * FROM t WHERE id = ?", r.FormValue("id")) // safe:sqli
 db.QueryContext(context.Background(), "SELECT * FROM t WHERE id = ?", r.FormValue("id")) // safe:sqli
}
func Request(r *http.Request) {
 http.Get(r.FormValue("url")) // finding:ssrf
 http.NewRequest(r.FormValue("method"), "https://example.com", nil) // safe:ssrf
 http.Post("https://example.com", r.FormValue("content-type"), nil) // safe:ssrf
}
func Response(w http.ResponseWriter, r *http.Request) {
 fmt.Fprint(w, r.FormValue("html")) // finding:xss
 w.Write([]byte(html.EscapeString(r.FormValue("html")))) // safe:xss
 var buf bytes.Buffer
 fmt.Fprint(&buf, r.FormValue("not-a-response")) // safe:xss
}
`
	dir := t.TempDir()
	for name, contents := range map[string]string{"go.mod": "module example.com/detectoroptions\n\ngo 1.25\n", "handlers.go": source} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOWORK", "off")
	p, err := wholeprogram.Load(context.Background(), wholeprogram.Config{Dir: dir, Patterns: []string{"."}, Scope: wholeprogram.ScopeSelected})
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name    string
		check   func(context.Context, *callgraph.Graph) []taint.Finding
		options func(context.Context, *callgraph.Graph, ...taint.Option) []taint.Finding
	}{
		{"cmdi", cmdi.Check, cmdi.CheckWithOptions},
		{"logi", logi.Check, logi.CheckWithOptions},
		{"ptrv", ptrv.Check, ptrv.CheckWithOptions},
		{"sqli", sqli.Check, sqli.CheckWithOptions},
		{"ssrf", ssrf.Check, ssrf.CheckWithOptions},
		{"xss", xss.Check, xss.CheckWithOptions},
	}
	normalize := func(findings []taint.Finding) []string {
		var result []string
		for _, f := range findings {
			result = append(result, fmt.Sprintf("%d:%s", f.Pos, f.Message))
		}
		sort.Strings(result)
		return result
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			ctx := context.Background()
			baseline := check.check(ctx, p.CallGraph)
			if len(baseline) != 1 {
				t.Fatalf("Check findings = %v, want exactly one unsafe call", baseline)
			}
			line := p.SSA.Fset.Position(baseline[0].Pos).Line
			if !strings.Contains(strings.Split(source, "\n")[line-1], "finding:"+check.name) {
				t.Fatalf("finding on unexpected line %d: %v", line, baseline)
			}
			for _, tc := range []struct {
				name string
				opts []taint.Option
			}{
				{"zero options", nil},
				{"selected occurrences", []taint.Option{taint.WithMatchPackages(p.MatchPackages...)}},
				{"last scope wins", []taint.Option{taint.WithMatchPackages(), taint.WithMatchPackages(p.MatchPackages...)}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					got := check.options(ctx, p.CallGraph, tc.opts...)
					if !reflect.DeepEqual(normalize(got), normalize(baseline)) {
						t.Fatalf("findings = %v, want Check parity %v", got, baseline)
					}
				})
			}
			for _, tc := range []struct {
				name   string
				option taint.Option
			}{
				{"empty scope", taint.WithMatchPackages()},
				{"nil identities", taint.WithMatchPackages(nil)},
				{"equal path different identity", taint.WithMatchPackages(types.NewPackage(p.MatchPackages[0].Path(), p.MatchPackages[0].Name()))},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if got := check.options(ctx, p.CallGraph, tc.option); len(got) != 0 {
						t.Fatalf("out-of-scope findings = %v", got)
					}
				})
			}
			t.Run("explicit context wins", func(t *testing.T) {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				if got := check.options(canceled, p.CallGraph, taint.WithMatchPackages(p.MatchPackages...), taint.WithContext(context.Background())); len(got) != 0 {
					t.Fatalf("canceled check returned %v", got)
				}
			})
		})
	}
}

func TestDetectorSelectedGenericAndClosureOccurrences(t *testing.T) {
	const source = `package handlers
import (
 "log"
 "net/http"
)
func genericLog[T ~string](r *http.Request, key T) {
 log.Print(r.FormValue(string(key))) // finding
}
func genericClean[T ~string](value T) { log.Print(value) } // safe
func Generic(r *http.Request) {
 genericLog(r, "message")
 genericClean("constant")
}
func Closure(r *http.Request) {
 unsafe := func() { log.Print(r.FormValue("message")) } // finding
 safe := func() { log.Print("constant") } // safe
 unsafe()
 safe()
}
`
	dir := t.TempDir()
	for name, contents := range map[string]string{"go.mod": "module example.com/detectoroccurrences\n\ngo 1.25\n", "handlers.go": source} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOWORK", "off")
	p, err := wholeprogram.Load(context.Background(), wholeprogram.Config{Dir: dir, Patterns: []string{"."}, Scope: wholeprogram.ScopeSelected})
	if err != nil {
		t.Fatal(err)
	}
	findings := logi.CheckWithOptions(context.Background(), p.CallGraph, taint.WithMatchPackages(p.MatchPackages...))
	if len(findings) != 2 {
		t.Fatalf("findings = %v, want generic and lexical-closure flows", findings)
	}
	seen := make(map[int]bool)
	for _, finding := range findings {
		line := p.SSA.Fset.Position(finding.Pos).Line
		if !strings.Contains(strings.Split(source, "\n")[line-1], "// finding") {
			t.Fatalf("unexpected finding on line %d", line)
		}
		seen[line] = true
	}
	if len(seen) != 2 {
		t.Fatalf("findings did not cover both unsafe callsites: %v", findings)
	}
	if got := logi.CheckWithOptions(context.Background(), p.CallGraph, taint.WithMatchPackages()); len(got) != 0 {
		t.Fatalf("empty scope returned %v", got)
	}
}
