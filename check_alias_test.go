package taint

import "testing"

// TestAliasedFieldStoreStillTainted pins the conservative direction for loads
// whose reaching stores go through a different SSA address value for the same
// field: the tainted store through pb must not be hidden from the load through
// pa by the identity-matched reaching-defs answer.
func TestAliasedFieldStoreStillTainted(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

type box struct{ q string }

func source() string { return "user" }

func cond() bool { return len("x") == 1 }

func main() {
	db := &sql.DB{}
	b := &box{}
	pa := &b.q
	pb := &b.q
	if cond() {
		*pb = source()
	} else {
		*pa = "clean"
	}
	db.Query(*pa)
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) != 1 {
		t.Fatalf("expected one diagnostic for the aliased tainted store, got %d", len(diagnostics))
	}
}

// TestLoopSiblingStoreDoesNotMaskTaint pins that a sibling store collected for
// a load has no kill power across a loop back edge: s[i] = "clean" cleans a
// different element than the one taintAll wrote in the previous iteration, so
// the tainted flow into the sink must still be reported.
func TestLoopSiblingStoreDoesNotMaskTaint(t *testing.T) {
	cg, pkgPath := detailedGraphForSource(t, `package main

import "database/sql"

func source() string { return "user" }

func taintAll(s []string) {
	for i := range s {
		s[i] = source()
	}
}

func main() {
	db := &sql.DB{}
	s := make([]string, 4)
	for i := 0; i < len(s); i++ {
		db.Query(s[i])
		taintAll(s)
		s[i] = "clean"
	}
}
`)

	diagnostics := CheckDetailed(
		cg,
		NewSources(pkgPath+".source"),
		NewSinks("(*database/sql.DB).Query"),
	)
	if len(diagnostics) == 0 {
		t.Fatal("expected a diagnostic: the loop-carried sibling store must not mask the tainted write")
	}
}
