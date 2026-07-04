package vulndb

import (
	"context"
	"testing"
	"testing/fstest"
)

// fixtureDB builds an in-memory database laid out like vulndb.zip, from a
// module index and a set of advisory JSON documents keyed by ID.
func fixtureDB(t *testing.T, modulesJSON string, entries map[string]string) Source {
	t.Helper()
	fsys := fstest.MapFS{
		"index/modules.json": &fstest.MapFile{Data: []byte(modulesJSON)},
	}
	for id, doc := range entries {
		fsys["ID/"+id+".json"] = &fstest.MapFile{Data: []byte(doc)}
	}
	return NewFSSource(fsys)
}

func TestClientAffectingEntries(t *testing.T) {
	modules := `[
		{"path":"golang.org/x/text","vulns":[{"id":"GO-2021-0113","fixed":"0.3.7"}]},
		{"path":"stdlib","vulns":[{"id":"GO-2022-0187","fixed":"1.7.6"}]},
		{"path":"github.com/gophish/gophish","vulns":[{"id":"GO-2025-3361"}]},
		{"path":"github.com/withdrawn/mod","vulns":[{"id":"GO-2099-9999"}]}
	]`
	entries := map[string]string{
		// Third-party with symbols.
		"GO-2021-0113": `{
			"id":"GO-2021-0113",
			"affected":[{
				"package":{"ecosystem":"Go","name":"golang.org/x/text"},
				"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.3.7"}]}],
				"ecosystem_specific":{"imports":[{"path":"golang.org/x/text/language","symbols":["Parse","MustParse"]}]}
			}],
			"database_specific":{"review_status":"REVIEWED"}
		}`,
		// stdlib with GOARCH constraint.
		"GO-2022-0187": `{
			"id":"GO-2022-0187",
			"affected":[{
				"package":{"ecosystem":"Go","name":"stdlib"},
				"ranges":[{"type":"SEMVER","events":[{"introduced":"1.6.0-0"},{"fixed":"1.7.6"},{"introduced":"1.8.0-0"},{"fixed":"1.8.2"}]}],
				"ecosystem_specific":{"imports":[{"path":"crypto/elliptic","goarch":["amd64"],"symbols":["p256SubInternal"]}]}
			}],
			"database_specific":{"review_status":"REVIEWED"}
		}`,
		// Module-level wildcard, unreviewed.
		"GO-2025-3361": `{
			"id":"GO-2025-3361",
			"affected":[{
				"package":{"ecosystem":"Go","name":"github.com/gophish/gophish"},
				"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}],
				"ecosystem_specific":{}
			}],
			"database_specific":{"review_status":"UNREVIEWED"}
		}`,
		// Withdrawn: must never be returned.
		"GO-2099-9999": `{
			"id":"GO-2099-9999",
			"withdrawn":"2024-08-21T16:25:56Z",
			"affected":[{
				"package":{"ecosystem":"Go","name":"github.com/withdrawn/mod"},
				"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]
			}]
		}`,
	}
	src := fixtureDB(t, modules, entries)
	c := NewClient(src)

	t.Run("affected versions match", func(t *testing.T) {
		got, err := c.AffectingEntries(context.Background(), []Module{
			{Path: "golang.org/x/text", Version: "0.3.5"},
			{Path: "stdlib", Version: "go1.7.0"},
			{Path: "github.com/gophish/gophish", Version: "0.11.0"},
			{Path: "github.com/withdrawn/mod", Version: "1.0.0"},
		})
		if err != nil {
			t.Fatal(err)
		}
		gotIDs := entryIDs(got)
		want := []string{"GO-2021-0113", "GO-2022-0187", "GO-2025-3361"}
		if !equalStrings(gotIDs, want) {
			t.Fatalf("AffectingEntries IDs = %v, want %v (withdrawn GO-2099-9999 must be excluded)", gotIDs, want)
		}
	})

	t.Run("fixed version filtered out", func(t *testing.T) {
		got, err := c.AffectingEntries(context.Background(), []Module{
			{Path: "golang.org/x/text", Version: "0.3.7"}, // exactly the fix
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("expected no advisories at the fixed version, got %v", entryIDs(got))
		}
	})

	t.Run("unknown module fetches nothing", func(t *testing.T) {
		got, err := c.AffectingEntries(context.Background(), []Module{
			{Path: "example.com/not/in/db", Version: "1.0.0"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("expected no advisories for an unknown module, got %v", entryIDs(got))
		}
	})

	t.Run("empty version matches conservatively", func(t *testing.T) {
		got, err := c.AffectingEntries(context.Background(), []Module{
			{Path: "stdlib", Version: ""},
		})
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"GO-2022-0187"}; !equalStrings(entryIDs(got), want) {
			t.Fatalf("empty version = %v, want %v", entryIDs(got), want)
		}
	})
}

func TestReviewStatusAndWithdrawn(t *testing.T) {
	reviewed := &Entry{DatabaseSpecific: &DatabaseSpecific{ReviewStatus: "REVIEWED"}}
	if reviewed.ReviewStatus() != ReviewStatusReviewed {
		t.Error("explicit REVIEWED not reported")
	}
	unreviewed := &Entry{DatabaseSpecific: &DatabaseSpecific{ReviewStatus: "UNREVIEWED"}}
	if unreviewed.ReviewStatus() != ReviewStatusUnreviewed {
		t.Error("UNREVIEWED not reported")
	}
	defaulted := &Entry{}
	if defaulted.ReviewStatus() != ReviewStatusReviewed {
		t.Error("absent review status should default to REVIEWED")
	}
}

func TestValidID(t *testing.T) {
	for _, bad := range []string{"", "GO/2022/0187", "../secrets", "GO-2022-0187.json", "a\\b"} {
		if err := validID(bad); err == nil {
			t.Errorf("validID(%q) = nil, want error", bad)
		}
	}
	if err := validID("GO-2022-0187"); err != nil {
		t.Errorf("validID(GO-2022-0187) = %v, want nil", err)
	}
}

func entryIDs(entries []*Entry) []string {
	ids := make([]string, len(entries))
	for i, e := range entries {
		ids[i] = e.ID
	}
	return ids
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
