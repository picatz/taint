package vulndb

import (
	"strings"

	"golang.org/x/mod/semver"
)

// AffectsVersion reports whether the affected entry covers the given module
// version. version is a Go module version, with or without a leading "v" and
// with or without a leading "go" (for the standard library and toolchain, a
// runtime version such as "go1.21.3" is accepted). An empty version, or one
// that cannot be parsed as SemVer, conservatively reports true so a caller
// never silently drops a potential finding on a version it cannot understand.
//
// The Go database expresses ranges as sorted SEMVER events. A version is
// affected when it falls in a half-open interval [introduced, fixed): at or
// after an "introduced" boundary and strictly before the next "fixed"
// boundary. A missing leading "introduced" defaults to all earlier versions
// ("0"), matching the OSV semantics the Go database relies on.
func (a Affected) AffectsVersion(version string) bool {
	v := canonicalSemver(version)
	if v == "" {
		// Unparseable or empty: do not rule the advisory out.
		return true
	}
	for _, r := range a.Ranges {
		if r.Type != "" && r.Type != "SEMVER" {
			// The Go database emits only SEMVER; anything else is not something
			// this matcher can reason about, so do not rule it out.
			return true
		}
		if rangeAffects(r, v) {
			return true
		}
	}
	return false
}

// rangeAffects reports whether a single SEMVER range covers canonical version
// v (already normalized to a comparable "vX.Y.Z" form). Events are processed
// in order: an "introduced" opens an affected interval, a "fixed" closes it.
func rangeAffects(r Range, v string) bool {
	affected := false
	for _, e := range r.Events {
		switch {
		case e.Introduced == "0":
			affected = true
		case e.Introduced != "":
			if semver.Compare(v, canonicalSemver(e.Introduced)) >= 0 {
				affected = true
			}
		case e.Fixed != "":
			if semver.Compare(v, canonicalSemver(e.Fixed)) < 0 {
				// v is before this fix; if an earlier introduced opened the
				// interval, v is affected.
				if affected {
					return true
				}
			} else {
				// v is at or after the fix: the interval this fix closes no
				// longer applies.
				affected = false
			}
		}
	}
	return affected
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
		affected := false
		for _, e := range r.Events {
			switch {
			case e.Introduced == "0":
				affected = true
			case e.Introduced != "":
				affected = semver.Compare(v, canonicalSemver(e.Introduced)) >= 0
			case e.Fixed != "":
				if affected && semver.Compare(v, canonicalSemver(e.Fixed)) < 0 {
					return strings.TrimPrefix(canonicalSemver(e.Fixed), "v")
				}
				affected = false
			}
		}
	}
	return ""
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
