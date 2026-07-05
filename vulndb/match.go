package vulndb

import (
	"slices"
	"strings"

	"golang.org/x/mod/semver"
)

// AffectsVersion reports whether the affected entry covers the given module
// version. version is a Go module version, with or without a leading "v" and
// with or without a leading "go" (for the standard library and toolchain, a
// runtime version such as "go1.21.3" is accepted). An empty version, or one
// that cannot be parsed as SemVer, conservatively reports true so a caller
// never silently drops a potential finding on a version it cannot understand.
// The same conservatism applies to structure this matcher cannot reason
// about: no ranges at all, a non-SEMVER range type, or a range whose events
// are missing or unparseable all report true rather than silently ruling the
// advisory out.
//
// Ranges are evaluated with the OSV algorithm: events are sorted by version
// (the spec requires consumers to sort; producers only "should"), then walked
// so a version is affected when it falls in a half-open interval
// [introduced, fixed), or at or below a "last_affected" boundary. A missing
// leading "introduced" defaults to all earlier versions ("0").
func (a Affected) AffectsVersion(version string) bool {
	v := canonicalSemver(version)
	if v == "" {
		// Unparseable or empty: do not rule the advisory out.
		return true
	}
	if len(a.Ranges) == 0 {
		// No ranges at all: nothing bounds the advisory, so treat every
		// version as affected (matching x/vuln's AffectsSemver).
		return true
	}
	for _, r := range a.Ranges {
		if r.Type != "" && r.Type != "SEMVER" {
			// The Go database emits only SEMVER; anything else is not something
			// this matcher can reason about, so do not rule it out.
			return true
		}
		if len(r.Events) == 0 {
			// A SEMVER range with no events is malformed; do not rule it out.
			return true
		}
		if affected, _ := walkEvents(r.Events, v); affected {
			return true
		}
	}
	return false
}

// FixedVersion returns the version that fixes the vulnerability for the given
// affected version, or "" when the advisory lists no applicable fix (an
// open-ended range). It reports the "fixed" boundary of the interval that
// contains version, so a caller can tell a user exactly what to upgrade to.
func (a Affected) FixedVersion(version string) string {
	v := canonicalSemver(version)
	if v == "" {
		return ""
	}
	for _, r := range a.Ranges {
		if r.Type != "" && r.Type != "SEMVER" {
			continue
		}
		if affected, fixed := walkEvents(r.Events, v); affected && fixed != "" {
			return strings.TrimPrefix(fixed, "v")
		}
	}
	return ""
}

// boundaryKind classifies a normalized range event. The numeric values carry
// no meaning; ordering between events is decided by version alone.
type boundaryKind uint8

const (
	kindIntroduced boundaryKind = iota
	kindFixed
	kindLastAffected
)

// boundary is a normalized range event: a canonical semver (or "" for the
// implicit "introduced at 0", which sorts before every valid version) and the
// event kind.
type boundary struct {
	v    string
	kind boundaryKind
}

// walkEvents evaluates a SEMVER range against canonical version v (already
// normalized to a comparable "vX.Y.Z" form) and reports whether v is affected
// and, when a fix boundary above v exists, that canonical fixed version.
//
// Events are normalized conservatively, then sorted, then walked with the OSV
// evaluation algorithm: an "introduced" at or below v marks it affected, a
// "fixed" at or below v clears it, and a "last_affected" strictly below v
// clears it. Normalization never lets bad data hide a finding: an
// unparseable "introduced" is widened to the beginning of time, an
// unparseable "fixed" or "last_affected" is dropped (an untrusted boundary
// must not close an interval), and a range with no "introduced" at all (the
// lenient fixed-first form; strict OSV requires one) gains an implicit one
// at 0.
func walkEvents(events []RangeEvent, v string) (affected bool, fixed string) {
	bounds := make([]boundary, 0, len(events)+1)
	for _, e := range events {
		switch {
		case e.Introduced == "0":
			// The spec's "beginning of time" sentinel. Kept distinct from
			// canonical "v0.0.0" so pseudo-versions and prereleases of v0.0.0
			// (which sort below it) are still covered.
			bounds = append(bounds, boundary{v: "", kind: kindIntroduced})
		case e.Introduced != "":
			c := canonicalSemver(e.Introduced)
			// An unparseable introduced boundary widens to 0: assume affected
			// rather than guessing where the interval starts.
			bounds = append(bounds, boundary{v: c, kind: kindIntroduced})
		case e.Fixed != "":
			if c := canonicalSemver(e.Fixed); c != "" {
				bounds = append(bounds, boundary{v: c, kind: kindFixed})
			}
		case e.LastAffected != "":
			if c := canonicalSemver(e.LastAffected); c != "" {
				bounds = append(bounds, boundary{v: c, kind: kindLastAffected})
			}
		}
	}
	if !slices.ContainsFunc(bounds, func(b boundary) bool { return b.kind == kindIntroduced }) {
		bounds = append(bounds, boundary{v: "", kind: kindIntroduced})
	}
	// Sort by version; "" (introduced at 0) is invalid semver and sorts first.
	// The sort is stable so producer order breaks ties, matching how a
	// spec-sorted range would arrive.
	slices.SortStableFunc(bounds, func(a, b boundary) int {
		return semver.Compare(a.v, b.v)
	})

	for _, b := range bounds {
		switch b.kind {
		case kindIntroduced:
			if b.v == "" || semver.Compare(v, b.v) >= 0 {
				affected = true
			}
		case kindFixed:
			if semver.Compare(v, b.v) >= 0 {
				affected = false
			} else if fixed == "" {
				// The first fix boundary above v: if v ends up affected, this
				// is the version that closes its interval.
				fixed = b.v
			}
		case kindLastAffected:
			if semver.Compare(v, b.v) > 0 {
				affected = false
			}
		}
	}
	return affected, fixed
}

// canonicalSemver normalizes a Go database version string into a form
// golang.org/x/mod/semver can compare: it strips a "go" prefix (toolchain and
// stdlib versions arrive as "go1.21.3"), ensures a leading "v", and canonicalizes.
// It returns "" when the input is empty or not valid SemVer.
func canonicalSemver(version string) string {
	s := strings.TrimSpace(version)
	if s == "" {
		return ""
	}
	s = strings.TrimPrefix(s, "go")
	if !strings.HasPrefix(s, "v") {
		s = "v" + s
	}
	if !semver.IsValid(s) {
		return ""
	}
	return semver.Canonical(s)
}
