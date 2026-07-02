package taint

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/picatz/taint/callgraphutil"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func TestCheckDetailedEvidenceOrder(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func wrapper(q string) string { return q }

func main() {
	db := &sql.DB{}
	db.Query(wrapper(source()))
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected one diagnostic, got %d", len(diagnostics))
	}

	gotKinds := evidenceKinds(diagnostics[0].Evidence)
	assertEvidenceOrder(t, gotKinds, EvidenceSourceMatch, EvidenceSinkMatch)
	assertEvidenceContains(t, gotKinds, EvidenceParameterMapping)
	assertEvidenceContains(t, gotKinds, EvidencePropagationStep)
	assertEvidenceContains(t, gotKinds, EvidenceSanitizerRejected)
}

func TestCheckDetailedAppliesValueSpecificSanitizer(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"html"
)

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	db.Query(html.EscapeString(source()))
}
`)

	withoutSanitizer := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(withoutSanitizer) != 1 {
		t.Fatalf("expected unsanitized check to report one diagnostic, got %d", len(withoutSanitizer))
	}

	withSanitizer := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
		WithSanitizers("html.EscapeString"),
	)
	if len(withSanitizer) != 0 {
		t.Fatalf("expected sanitizer to suppress diagnostic, got %d", len(withSanitizer))
	}
}

func TestCheckDetailedSanitizerWrapperSuppressesDiagnostic(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"html"
)

func source() string { return "user" }

func clean(q string) string {
	return html.EscapeString(q)
}

func main() {
	db := &sql.DB{}
	db.Query(clean(source()))
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
		WithSanitizers("html.EscapeString"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected sanitizer wrapper to suppress diagnostic, got %d", len(diagnostics))
	}
}

func TestCheckDetailedSanitizerWrapperThroughIdentitySuppressesDiagnostic(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"html"
)

func source() string { return "user" }

func passthrough(q string) string {
	return q
}

func clean(q string) string {
	return passthrough(html.EscapeString(q))
}

func main() {
	db := &sql.DB{}
	db.Query(clean(source()))
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
		WithSanitizers("html.EscapeString"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected sanitizer wrapper through identity helper to suppress diagnostic, got %d", len(diagnostics))
	}
}

func TestCheckDetailedPartiallySanitizedWrapperStillReports(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"html"
)

func source() string { return "user" }

func clean(q string) string {
	return html.EscapeString(q)
}

func main() {
	db := &sql.DB{}
	db.Query(clean(source()) + source())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
		WithSanitizers("html.EscapeString"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected partially sanitized wrapper expression to report one diagnostic, got %d", len(diagnostics))
	}
	assertEvidenceRule(t, diagnostics[0].Evidence, EvidenceSanitizerRejected, "html.EscapeString")
}

func TestCheckDetailedSanitizerEvidenceIsScopedToTaintedArgument(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"html"
)

func source() string { return "user" }

func clean(q string) string {
	return html.EscapeString(q)
}

func main() {
	db := &sql.DB{}
	db.Query(clean(source()), source())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
		WithSanitizers("html.EscapeString"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected tainted sibling argument to report one diagnostic, got %d", len(diagnostics))
	}
	for _, evidence := range diagnostics[0].Evidence {
		if evidence.Kind == EvidenceSanitizerApplied {
			t.Fatalf("did not expect sanitizer evidence from clean sibling argument: %#v", diagnostics[0].Evidence)
		}
		if evidence.Rule == "html.EscapeString" {
			t.Fatalf("did not expect html.EscapeString evidence on tainted sibling argument: %#v", diagnostics[0].Evidence)
		}
	}
}

func TestCheckDetailedSanitizerIgnoresLaterUnsanitizedStore(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"html"
)

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	q := html.EscapeString(source())
	p := &q
	db.Query(*p)
	*p = source()
	_ = *p
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
		WithSanitizers("html.EscapeString"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected sanitizer to ignore later unsanitized store, got %d", len(diagnostics))
	}
}

func TestCheckDetailedExtraSourcesAndSinks(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	db.Query(source())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(),
		NewSinks(),
		WithExtraSources(pkgPath+".source"),
		WithExtraSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected extra source/sink options to report one diagnostic, got %d", len(diagnostics))
	}
}

func TestCheckDetailedMaxSummaryDepthCanBeRaised(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }
func wrap1() string { return source() }
func wrap2() string { return wrap1() }
func wrap3() string { return wrap2() }
func wrap4() string { return wrap3() }
func wrap5() string { return wrap4() }
func wrap6() string { return wrap5() }
func wrap7() string { return wrap6() }
func wrap8() string { return wrap7() }
func wrap9() string { return wrap8() }

func main() {
	db := &sql.DB{}
	db.Query(wrap9())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
		WithMaxSummaryDepth(9),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected raised summary depth to report one diagnostic, got %d", len(diagnostics))
	}
}

func TestCheckDetailedDefaultSummaryDepthRemainsBounded(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }
func wrap1() string { return source() }
func wrap2() string { return wrap1() }
func wrap3() string { return wrap2() }
func wrap4() string { return wrap3() }
func wrap5() string { return wrap4() }
func wrap6() string { return wrap5() }
func wrap7() string { return wrap6() }
func wrap8() string { return wrap7() }
func wrap9() string { return wrap8() }

func main() {
	db := &sql.DB{}
	db.Query(wrap9())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected default summary depth to remain bounded, got %d diagnostics", len(diagnostics))
	}

	diagnostics = CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
		WithMaxSummaryDepth(0),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected non-positive summary depth to use the bounded default, got %d diagnostics", len(diagnostics))
	}
}

// TestReceiverPropagationPrefersPreciseReturnAnalysis is the engine-level
// regression for the gorilla-mux false positive. A method returning only an
// error that does not embed its receiver's data must not be marked tainted
// just because the receiver type is a configured source.
func TestReceiverPropagationPrefersPreciseReturnAnalysis(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "log"

type Req struct{ name string }

// Validate returns a framework error that mentions only constants. The
// receiver carries data, but none of that data flows into the returned
// error value.
func (r *Req) Validate() error {
	if r == nil {
		return errConst
	}
	return nil
}

var errConst = errStr("invalid request")

type errStr string

func (e errStr) Error() string { return string(e) }

func main() {
	r := &Req{name: "x"}
	if err := r.Validate(); err != nil {
		log.Printf("validate: %v", err)
	}
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources("*"+pkgPath+".Req"),
		NewSinks("log.Printf"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected no diagnostics — error return does not embed receiver data — got %d", len(diagnostics))
	}
}

// TestReceiverPropagationCatchesPreciseEmbedding is the positive complement:
// a method whose error value DOES contain receiver data must still be
// flagged. This proves the precise walker is actually doing work, not just
// silently suppressing the previous false positive.
func TestReceiverPropagationCatchesPreciseEmbedding(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"fmt"
	"log"
)

type Req struct{ name string }

// Validate returns an error containing receiver data — the precise return
// walker must see this and mark the result tainted.
func (r *Req) Validate() error {
	return fmt.Errorf("bad name: %s", r.name)
}

func main() {
	r := &Req{name: "x"}
	if err := r.Validate(); err != nil {
		log.Printf("validate: %v", err)
	}
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources("*"+pkgPath+".Req"),
		NewSinks("log.Printf"),
	)
	if len(diagnostics) == 0 {
		t.Fatal("expected a diagnostic — error value embeds receiver data — got none")
	}
}

func TestCheckDetailedOverlappingSourceRulesAreDeterministic(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

type Req struct{}

func (*Req) ProtoMessage() {}

func sink(*Req) {}

func handle(r *Req) {
	sink(r)
}

func main() {
	handle(&Req{})
}
`)

	want := "*" + pkgPath + ".Req"
	for i := range 20 {
		diagnostics := CheckDetailed(
			cg,
			NewSources("google.golang.org/protobuf/proto.Message", want),
			NewSinks(pkgPath+".sink"),
		)
		if len(diagnostics) != 1 {
			t.Fatalf("iteration %d: expected one diagnostic, got %d", i, len(diagnostics))
		}
		if got := diagnostics[0].Result.SourceType; got != want {
			t.Fatalf("iteration %d: SourceType = %q, want %q", i, got, want)
		}
	}
}

func TestCheckDetailedDoesNotTreatUnusedCallbackArgumentAsReachable(t *testing.T) {
	cg, _ := detailedGraphForSource(t, `package main

import (
	"log"
	"net/http"
)

func ignore(func(*http.Request)) {}

func main() {
	ignore(func(r *http.Request) {
		log.Print(r.URL.Query().Get("q"))
	})
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources("*net/http.Request"),
		NewSinks("log.Print"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected no diagnostics for callback that is never invoked, got %d", len(diagnostics))
	}
}

func TestCheckDetailedTreatsInvokedCallbackArgumentAsReachable(t *testing.T) {
	cg, _ := detailedGraphForSource(t, `package main

import (
	"log"
	"net/http"
)

func invoke(cb func(*http.Request)) {
	cb(nil)
}

func main() {
	invoke(func(r *http.Request) {
		log.Print(r.URL.Query().Get("q"))
	})
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources("*net/http.Request"),
		NewSinks("log.Print"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected one diagnostic for callback that is invoked, got %d", len(diagnostics))
	}
}

func TestCheckDetailedPropagatesThroughStringTransforms(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"strings"
)

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	db.Query(strings.TrimSpace(source()))
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected one diagnostic through strings.TrimSpace, got %d", len(diagnostics))
	}
}

func TestCheckDetailedPropagatesThroughStringsRepeat(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"strings"
)

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	db.Query(strings.Repeat(source(), 2))
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected one diagnostic through strings.Repeat, got %d", len(diagnostics))
	}
}

func TestCheckDetailedPropagatesThroughPhi(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"os"
)

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	q := "safe"
	if len(os.Args) > 0 {
		q = source()
	}
	db.Query(q)
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected one diagnostic through phi value, got %d", len(diagnostics))
	}
}

func TestCheckDetailedPropagatesThroughStructFieldRead(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

type request struct {
	query string
}

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	r := request{query: source()}
	db.Query(r.query)
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected one diagnostic through struct field read, got %d", len(diagnostics))
	}
}

func TestCheckDetailedFindsSinkCalledThroughMethodValue(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	query := db.Query
	query(source())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected one diagnostic through database/sql method value, got %d", len(diagnostics))
	}
}

func TestCheckDetailedPropagatesThroughAppendAndJoin(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"strings"
)

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	parts := []string{"select "}
	parts = append(parts, source())
	db.Query(strings.Join(parts, ""))
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected one diagnostic through append and strings.Join, got %d", len(diagnostics))
	}
}

func TestCheckDetailedPropagatesThroughStringsBuilder(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"strings"
)

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	var b strings.Builder
	b.WriteString("select ")
	b.WriteString(source())
	db.Query(b.String())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected one diagnostic through strings.Builder, got %d", len(diagnostics))
	}
}

func TestCheckDetailedDirectHelperWritesScalarPointer(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func set(p *string, q string) {
	*p = q
}

func main() {
	db := &sql.DB{}
	q := "select 1"
	set(&q, source())
	db.Query(q)
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected one diagnostic through direct scalar pointer helper write, got %d", len(diagnostics))
	}
}

func TestCheckDetailedIgnoresLaterDirectHelperScalarPointerWrite(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func set(p *string, q string) {
	*p = q
}

func main() {
	db := &sql.DB{}
	q := "select 1"
	db.Query(q)
	set(&q, source())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected later direct helper scalar pointer write to stay clean, got %d", len(diagnostics))
	}
}

func TestCheckDetailedPointerLoadUsesLatestStoreBeforeLoad(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	q := source()
	p := &q
	q = "safe"
	db.Query(*p)
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected overwritten pointer load to stay clean, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedDirectHelperScalarPointerWriteKilledByCallerStore(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func set(p *string, q string) {
	*p = q
}

func main() {
	db := &sql.DB{}
	q := "select 1"
	set(&q, source())
	q = "safe"
	db.Query(q)
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected caller overwrite to kill direct helper scalar write, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedConditionalDirectHelperStoreDoesNotKillCallerValue(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"os"
)

func source() string { return "user" }

func maybeSet(p *string) {
	if len(os.Args) > 0 {
		*p = "safe"
	}
}

func main() {
	db := &sql.DB{}
	q := source()
	maybeSet(&q)
	db.Query(q)
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected conditional direct helper store to preserve caller taint, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedPointerLoadTaintedFromReachingBranchStore(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"os"
)

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	q := "safe"
	p := &q
	if len(os.Args) > 0 {
		q = source()
	} else {
		q = "still safe"
	}
	db.Query(*p)
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected reaching branch pointer store to report, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedMapLookupIgnoresDifferentConstantKeyUpdate(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	m := map[string]string{}
	m["other"] = source()
	db.Query(m["q"])
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected different constant map key update to stay clean, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedMapLookupIgnoresLaterSameKeyUpdate(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	m := map[string]string{}
	db.Query(m["q"])
	m["q"] = source()
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected later map update to stay clean, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedMapLookupUnknownKeyRemainsConservative(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func key() string { return "q" }

func main() {
	db := &sql.DB{}
	m := map[string]string{}
	m["q"] = source()
	db.Query(m[key()])
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected unknown map lookup key to report reaching tainted update, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedMapLiteralTaintReachesLookup(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	m := map[string]string{"q": source()}
	db.Query(m["q"])
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected map literal taint to reach lookup, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedDirectHelperWritesStringsBuilder(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"strings"
)

func source() string { return "user" }

func fill(b *strings.Builder, q string) {
	b.WriteString(q)
}

func main() {
	db := &sql.DB{}
	var b strings.Builder
	fill(&b, source())
	db.Query(b.String())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected one diagnostic through direct strings.Builder helper write, got %d", len(diagnostics))
	}
}

func TestCheckDetailedPropagatesThroughFormattedStringsBuilderWrite(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"fmt"
	"strings"
)

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	var b strings.Builder
	fmt.Fprintf(&b, "select %s", source())
	db.Query(b.String())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected one diagnostic through fmt.Fprintf strings.Builder write, got %d", len(diagnostics))
	}
}

func TestCheckDetailedDirectHelperWritesFormattedStringsBuilder(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"fmt"
	"strings"
)

func source() string { return "user" }

func fill(b *strings.Builder, q string) {
	fmt.Fprintf(b, "select %s", q)
}

func main() {
	db := &sql.DB{}
	var b strings.Builder
	fill(&b, source())
	db.Query(b.String())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected one diagnostic through direct fmt.Fprintf builder helper write, got %d", len(diagnostics))
	}
}

func TestCheckDetailedDoesNotTaintBuilderStringFromLaterWrite(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"strings"
)

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	var b strings.Builder
	b.WriteString("select 1")
	db.Query(b.String())
	b.WriteString(source())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected no diagnostic from later strings.Builder write, got %d", len(diagnostics))
	}
}

func TestCheckDetailedDoesNotTaintBuilderStringFromLaterFormattedWrite(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"fmt"
	"strings"
)

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	var b strings.Builder
	b.WriteString("select 1")
	db.Query(b.String())
	fmt.Fprintf(&b, " where id = %s", source())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected no diagnostic from later fmt.Fprintf strings.Builder write, got %d", len(diagnostics))
	}
}

func TestCheckDetailedPropagatesThroughBytesBuffer(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"bytes"
	"database/sql"
)

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	var b bytes.Buffer
	b.WriteString("select ")
	b.WriteString(source())
	db.Query(b.String())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected one diagnostic through bytes.Buffer, got %d", len(diagnostics))
	}
}

func TestCheckDetailedPropagatesThroughIOWriteStringBuffer(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"bytes"
	"database/sql"
	"io"
)

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	var b bytes.Buffer
	io.WriteString(&b, "select ")
	io.WriteString(&b, source())
	db.Query(b.String())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected one diagnostic through io.WriteString bytes.Buffer write, got %d", len(diagnostics))
	}
}

func TestCheckDetailedDirectHelperWritesIOWriteStringBuffer(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"bytes"
	"database/sql"
	"io"
)

func source() string { return "user" }

func fill(b *bytes.Buffer, q string) {
	io.WriteString(b, q)
}

func main() {
	db := &sql.DB{}
	var b bytes.Buffer
	fill(&b, source())
	db.Query(b.String())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected one diagnostic through direct io.WriteString buffer helper write, got %d", len(diagnostics))
	}
}

func TestCheckDetailedStringsBuilderResetClearsPriorTaint(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"strings"
)

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	var b strings.Builder
	b.WriteString(source())
	b.Reset()
	b.WriteString("select 1")
	db.Query(b.String())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected strings.Builder Reset to clear prior taint, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedBytesBufferResetClearsPriorTaintBeforeBytes(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"bytes"
	"database/sql"
)

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	var b bytes.Buffer
	b.WriteString(source())
	b.Reset()
	b.WriteString("select 1")
	db.Query(string(b.Bytes()))
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected bytes.Buffer Reset to clear prior taint before Bytes, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedBytesBufferTruncateZeroClearsPriorTaint(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"bytes"
	"database/sql"
)

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	var b bytes.Buffer
	b.WriteString(source())
	b.Truncate(0)
	b.WriteString("select 1")
	db.Query(b.String())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected bytes.Buffer Truncate(0) to clear prior taint, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedBytesBufferTruncateNonZeroPreservesPriorTaint(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"bytes"
	"database/sql"
)

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	var b bytes.Buffer
	b.WriteString("x" + source())
	b.Truncate(1)
	db.Query(b.String())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected non-zero bytes.Buffer Truncate to preserve prior taint, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedBytesBufferTruncateUnknownPreservesPriorTaint(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"bytes"
	"database/sql"
	"os"
)

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	var b bytes.Buffer
	b.WriteString(source())
	b.Truncate(len(os.Args))
	db.Query(b.String())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected unknown bytes.Buffer Truncate to preserve prior taint, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedDirectHelperBufferResetClearsPriorHelperWrite(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"strings"
)

func source() string { return "user" }

func fill(b *strings.Builder, q string) {
	b.WriteString(q)
	b.Reset()
}

func main() {
	db := &sql.DB{}
	var b strings.Builder
	fill(&b, source())
	b.WriteString("select 1")
	db.Query(b.String())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected direct helper Reset to clear prior helper write, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedExecCommandVariadicSliceUsesReachingStore(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "os/exec"

func source() string { return "user" }

func main() {
	args := []string{"-c", "safe"}
	args[1] = source()
	exec.Command("sh", args...)
	args[1] = "later"
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("os/exec.Command"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected reaching variadic shell command store to report, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedExecCommandVariadicSliceIgnoresOverwrittenEarlierStore(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "os/exec"

func source() string { return "user" }

func main() {
	args := []string{"-c", source()}
	args[1] = "safe"
	exec.Command("sh", args...)
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("os/exec.Command"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected overwritten earlier variadic shell command store to stay clean, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedRecordsNestedSanitizerEvidenceThroughLoad(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"html"
)

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	q := html.EscapeString(source())
	p := &q
	db.Query(*p + source())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
		WithSanitizers("html.EscapeString"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected one diagnostic for partially sanitized expression, got %d", len(diagnostics))
	}
	assertEvidenceRule(t, diagnostics[0].Evidence, EvidenceSanitizerRejected, "html.EscapeString")
}

func TestCheckDetailedPropagatesCallbackInvocationArguments(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func invoke(cb func(string)) {
	cb(source())
}

func main() {
	db := &sql.DB{}
	invoke(func(q string) {
		db.Query(q)
	})
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected one diagnostic through callback invocation argument, got %d", len(diagnostics))
	}
}

func TestCheckDetailedDoesNotTaintEarlierLoadFromLaterStore(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	q := "safe"
	p := &q
	db.Query(*p)
	q = source()
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected no diagnostic from later store, got %d", len(diagnostics))
	}
}

func TestCheckDetailedDoesNotTaintEarlierLoadFromLaterBranchStore(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"os"
)

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	q := "safe"
	p := &q
	db.Query(*p)
	if len(os.Args) > 0 {
		q = source()
	}
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected no diagnostic from later branch store, got %d", len(diagnostics))
	}
}

func TestCheckDetailedDoesNotTaintParameterFromUnrelatedLaterUse(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func query(db *sql.DB, q string) {
	db.Query(q)
	_ = source() + q
}

func main() {
	db := &sql.DB{}
	query(db, "safe")
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected no diagnostic from unrelated later parameter use, got %d", len(diagnostics))
	}
}

func TestCheckDetailedDoesNotTaintFieldFromUnrelatedLaterUse(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

type request struct {
	query string
}

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	r := request{query: "safe"}
	db.Query(r.query)
	_ = source() + r.query
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected no diagnostic from unrelated later field use, got %d", len(diagnostics))
	}
}

func TestCheckDetailedMapsInvokeArgumentsToMethodParameters(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

type runner interface {
	run(string)
}

type impl struct {
	db *sql.DB
}

func source() string { return "user" }

func (i impl) run(q string) {
	i.db.Query(q)
}

func main() {
	var r runner = impl{db: &sql.DB{}}
	r.run(source())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected one diagnostic through interface invoke argument, got %d", len(diagnostics))
	}
}

func TestCheckDetailedPropagatesThroughBufferWriteByte(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"bytes"
	"database/sql"
)

func source() byte { return 'x' }

func main() {
	db := &sql.DB{}
	var b bytes.Buffer
	b.WriteString("select ")
	b.WriteByte(source())
	db.Query(b.String())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected WriteByte taint to propagate, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedPropagatesThroughBufferWriteRune(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"bytes"
	"database/sql"
)

func source() rune { return 'x' }

func main() {
	db := &sql.DB{}
	var b bytes.Buffer
	b.WriteString("select ")
	b.WriteRune(source())
	db.Query(b.String())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected WriteRune taint to propagate, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedPropagatesThroughBuilderWriteByte(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"database/sql"
	"strings"
)

func source() byte { return 'x' }

func main() {
	db := &sql.DB{}
	var b strings.Builder
	b.WriteString("select ")
	b.WriteByte(source())
	db.Query(b.String())
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected strings.Builder.WriteByte taint to propagate, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedPropagatesThroughBufferNextRead(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import (
	"bytes"
	"database/sql"
)

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	var b bytes.Buffer
	b.WriteString(source())
	db.Query(string(b.Next(5)))
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected bytes.Buffer.Next read to propagate buffered taint, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedMapDeleteClearsPriorTaint(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	m := map[string]string{}
	m["q"] = source()
	delete(m, "q")
	db.Query(m["q"])
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected delete(m, \"q\") to kill prior taint, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedMapDeleteWithUnknownKeyPreservesTaint(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func key() string { return "other" }

func main() {
	db := &sql.DB{}
	m := map[string]string{}
	m["q"] = source()
	delete(m, key())
	db.Query(m["q"])
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected delete with unknown key to preserve taint, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedMapDeleteDifferentKeyPreservesTaint(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	m := map[string]string{}
	m["q"] = source()
	delete(m, "other")
	db.Query(m["q"])
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected delete on different key to preserve taint, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedMapClearKillsPriorTaint(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	m := map[string]string{}
	m["q"] = source()
	clear(m)
	db.Query(m["q"])
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected clear(m) to kill prior taint, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedHelperMapWriteReachesLookup(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func put(m map[string]string, k, v string) {
	m[k] = v
}

func main() {
	db := &sql.DB{}
	m := map[string]string{}
	put(m, "q", source())
	db.Query(m["q"])
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected helper map write to reach lookup, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedHelperMapDeleteKillsPriorTaint(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func drop(m map[string]string, k string) {
	delete(m, k)
}

func main() {
	db := &sql.DB{}
	m := map[string]string{}
	m["q"] = source()
	drop(m, "q")
	db.Query(m["q"])
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected helper delete to kill prior taint, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedHelperMapClearKillsPriorTaint(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func wipe(m map[string]string) {
	clear(m)
}

func main() {
	db := &sql.DB{}
	m := map[string]string{}
	m["q"] = source()
	wipe(m)
	db.Query(m["q"])
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected helper clear(m) to kill prior taint, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedAggregateUnrelatedFieldFromHelperWriteStaysClean(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

type S struct {
	A string
	B string
}

func source() string { return "user" }

func setA(s *S, v string) {
	s.A = v
}

func main() {
	db := &sql.DB{}
	s := &S{B: "select 1"}
	setA(s, source())
	db.Query(s.B)
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected unrelated field load to stay clean after helper field write, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedAggregateSameFieldFromHelperWritePropagates(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

type S struct {
	A string
	B string
}

func source() string { return "user" }

func setA(s *S, v string) {
	s.A = v
}

func main() {
	db := &sql.DB{}
	s := &S{}
	setA(s, source())
	db.Query(s.A)
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected same-field helper write to propagate, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedAggregateUnrelatedIndexFromHelperWriteStaysClean(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func setFirst(a *[2]string, v string) {
	a[0] = v
}

func main() {
	db := &sql.DB{}
	var a [2]string
	a[1] = "select 1"
	setFirst(&a, source())
	db.Query(a[1])
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected unrelated array index load to stay clean after helper write, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedLoopCarriedHelperStoreReachesLaterLoad(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func set(p *string, q string) {
	*p = q
}

func main() {
	db := &sql.DB{}
	q := "safe"
	for i := 0; i < 3; i++ {
		if i == 1 {
			set(&q, source())
		}
	}
	db.Query(q)
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected loop-carried helper store to reach later load, got %d diagnostics", len(diagnostics))
	}
}

func TestCheckDetailedLoopCarriedFieldStoreReachesLaterLoad(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

type S struct {
	V string
}

func source() string { return "user" }

func main() {
	db := &sql.DB{}
	s := &S{V: "safe"}
	for i := 0; i < 3; i++ {
		if i == 1 {
			s.V = source()
		}
	}
	db.Query(s.V)
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected loop-carried field store to reach later load, got %d diagnostics", len(diagnostics))
	}
}

func evidenceKinds(evidence []Evidence) []EvidenceKind {
	kinds := make([]EvidenceKind, 0, len(evidence))
	for _, entry := range evidence {
		kinds = append(kinds, entry.Kind)
	}
	return kinds
}

func assertEvidenceContains(t *testing.T, kinds []EvidenceKind, want EvidenceKind) {
	t.Helper()
	if slices.Contains(kinds, want) {
		return
	}
	t.Fatalf("expected evidence kind %s in %v", want, kinds)
}

func assertEvidenceOrder(t *testing.T, kinds []EvidenceKind, first, second EvidenceKind) {
	t.Helper()
	firstIndex, secondIndex := -1, -1
	for i, kind := range kinds {
		if kind == first && firstIndex < 0 {
			firstIndex = i
		}
		if kind == second && secondIndex < 0 {
			secondIndex = i
		}
	}
	if firstIndex < 0 || secondIndex < 0 {
		t.Fatalf("expected evidence kinds %s and %s in %v", first, second, kinds)
	}
	if firstIndex >= secondIndex {
		t.Fatalf("expected %s before %s in %v", first, second, kinds)
	}
}

func assertEvidenceRule(t *testing.T, evidence []Evidence, kind EvidenceKind, rule string) {
	t.Helper()
	for _, entry := range evidence {
		if entry.Kind == kind && entry.Rule == rule {
			return
		}
	}
	t.Fatalf("expected evidence kind %s with rule %q in %#v", kind, rule, evidence)
}

func detailedGraphForSource(t *testing.T, src string) (*callgraph.Graph, string) {
	t.Helper()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/detailed\n\ngo 1.24.4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	pkgs, err := packages.Load(&packages.Config{
		Mode: packages.NeedName |
			packages.NeedDeps |
			packages.NeedFiles |
			packages.NeedCompiledGoFiles |
			packages.NeedTypes |
			packages.NeedImports |
			packages.NeedSyntax |
			packages.NeedTypesInfo,
		Context: context.Background(),
		Dir:     dir,
		Tests:   false,
	}, "./...")
	if err != nil {
		t.Fatal(err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("package load failed")
	}

	ssaProg, ssaPkgs := ssautil.Packages(pkgs, ssa.InstantiateGenerics)
	ssaProg.Build()
	for _, pkg := range ssaPkgs {
		pkg.Build()
	}

	mainPkgs := ssautil.MainPackages(ssaPkgs)
	if len(mainPkgs) != 1 {
		t.Fatalf("expected one main package, got %d", len(mainPkgs))
	}
	mainFn := mainPkgs[0].Func("main")
	if mainFn == nil {
		t.Fatal("main function not found")
	}

	var srcFns []*ssa.Function
	var addFunction func(*ssa.Function)
	addFunction = func(fn *ssa.Function) {
		srcFns = append(srcFns, fn)
		for _, anon := range fn.AnonFuncs {
			addFunction(anon)
		}
	}
	for _, pkg := range ssaPkgs {
		for _, member := range pkg.Members {
			fn, ok := member.(*ssa.Function)
			if !ok || fn.Object() == nil || fn.Object().Name() == "_" {
				continue
			}
			addFunction(fn)
		}
	}

	cg, err := callgraphutil.NewGraph(mainFn, srcFns...)
	if err != nil {
		t.Fatal(err)
	}
	return cg, mainFn.Pkg.Pkg.Path()
}
