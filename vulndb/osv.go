// Package vulndb reads the Go vulnerability database (https://vuln.go.dev),
// the authoritative source of GO-YYYY-NNNN advisories that backs govulncheck.
//
// It provides just enough of the OSV schema to answer the questions a scanner
// asks: which advisories affect a module at a version, which packages and
// symbols each advisory names, and how to reach the data over the network or
// from a local mirror. The types here are a deliberately small, plain-JSON
// subset of the full OSV schema. The official schema bindings
// (github.com/ossf/osv-schema/bindings/go) became protobuf-generated and no
// longer decode the Go database's plain JSON without protojson, and their
// ecosystem_specific field (where Go's package and symbol data lives) is
// untyped regardless, so a focused local definition is both smaller and more
// precise for a Go-only consumer.
package vulndb

import (
	"time"
)

// Entry is a single OSV advisory as served by the Go vulnerability database at
// https://vuln.go.dev/ID/GO-YYYY-NNNN.json. Only the fields a scanner uses are
// modeled; unknown fields are ignored on decode.
type Entry struct {
	// SchemaVersion is the OSV schema version, e.g. "1.3.1".
	SchemaVersion string `json:"schema_version,omitempty"`
	// ID is the Go advisory identifier, e.g. "GO-2022-0187".
	ID string `json:"id"`
	// Modified is when the advisory last changed. Used for incremental sync.
	Modified time.Time `json:"modified,omitzero"`
	// Published is when the advisory was first published.
	Published time.Time `json:"published,omitzero"`
	// Withdrawn, when non-nil, marks the advisory as retracted. Withdrawn
	// advisories remain in the database but must not produce findings.
	Withdrawn *time.Time `json:"withdrawn,omitempty"`
	// Aliases are external identifiers for the same vulnerability, typically
	// CVE and GHSA IDs.
	Aliases []string `json:"aliases,omitempty"`
	// Related lists loosely associated identifiers.
	Related []string `json:"related,omitempty"`
	// Summary is a one-line title.
	Summary string `json:"summary,omitempty"`
	// Details is the full prose description.
	Details string `json:"details,omitempty"`
	// Affected lists the affected modules, their version ranges, and their
	// vulnerable packages and symbols.
	Affected []Affected `json:"affected,omitempty"`
	// References are supporting links (fix commits, reports, advisories).
	References []Reference `json:"references,omitempty"`
	// DatabaseSpecific carries the Go database's own metadata, notably the
	// review status.
	DatabaseSpecific *DatabaseSpecific `json:"database_specific,omitempty"`
}

// Affected describes one module affected by an advisory: the versions in which
// it is vulnerable and, for a reviewed advisory, the specific packages and
// symbols.
type Affected struct {
	// Package identifies the affected module.
	Package Package `json:"package"`
	// Ranges carry the affected version intervals. The Go database uses only
	// SEMVER ranges.
	Ranges []Range `json:"ranges,omitempty"`
	// EcosystemSpecific carries the Go package and symbol data. It is absent
	// for module-level advisories (the majority of the database).
	EcosystemSpecific *EcosystemSpecific `json:"ecosystem_specific,omitempty"`
	// DatabaseSpecific carries per-affected metadata, notably the canonical
	// source URL.
	DatabaseSpecific map[string]any `json:"database_specific,omitempty"`
}

// Package identifies a module within an ecosystem. In the Go database the
// standard library is the pseudo-module "stdlib" and the toolchain is
// "toolchain"; everything else is a module import path.
type Package struct {
	// Ecosystem is always "Go" for entries in this database.
	Ecosystem string `json:"ecosystem"`
	// Name is the module path, "stdlib", or "toolchain".
	Name string `json:"name"`
}

// Range is a set of version events describing where a vulnerability was
// introduced and fixed. The Go database emits only Type "SEMVER".
type Range struct {
	// Type is the range kind; "SEMVER" for all Go entries.
	Type string `json:"type"`
	// Events are the sorted introduced/fixed boundaries.
	Events []RangeEvent `json:"events,omitempty"`
}

// RangeEvent is one boundary in a version range. Exactly one field is set.
// Go versions are bare SemVer without the "v" prefix (e.g. "1.7.6"); the
// standard library uses an "N.M.0-0" prerelease sentinel as the introduced
// boundary so pre-release toolchains sort as affected.
type RangeEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// EcosystemSpecific carries the Go-specific package and symbol data, decoded
// from the OSV ecosystem_specific object.
type EcosystemSpecific struct {
	// Imports lists the vulnerable packages, each optionally naming the
	// vulnerable symbols and platform constraints.
	Imports []Import `json:"imports,omitempty"`
}

// Import names a vulnerable package and, when the advisory has been reviewed
// to symbol precision, the vulnerable symbols within it.
type Import struct {
	// Path is the package import path.
	Path string `json:"path"`
	// GOOS constrains the vulnerability to these operating systems; empty
	// means all.
	GOOS []string `json:"goos,omitempty"`
	// GOARCH constrains the vulnerability to these architectures; empty means
	// all.
	GOARCH []string `json:"goarch,omitempty"`
	// Symbols names the vulnerable functions and methods, package-relative and
	// with pointer receivers spelled without a star (e.g. "Conn.Query"). An
	// empty list means every symbol in the package is vulnerable.
	Symbols []string `json:"symbols,omitempty"`
}

// Reference is a supporting link for an advisory.
type Reference struct {
	// Type is the reference kind, e.g. "FIX", "REPORT", "WEB".
	Type string `json:"type,omitempty"`
	// URL is the link target.
	URL string `json:"url,omitempty"`
}

// DatabaseSpecific carries the Go database's metadata for an advisory.
type DatabaseSpecific struct {
	// URL is the human-facing advisory page.
	URL string `json:"url,omitempty"`
	// ReviewStatus is "REVIEWED" or "UNREVIEWED". Reviewed advisories carry
	// curated package and symbol data; unreviewed ones are auto-imported and
	// are almost always module-level only.
	ReviewStatus string `json:"review_status,omitempty"`
}

// ReviewStatus classifies how thoroughly an advisory has been triaged.
type ReviewStatus string

const (
	// ReviewStatusReviewed marks a curated advisory that may carry package and
	// symbol precision.
	ReviewStatusReviewed ReviewStatus = "REVIEWED"
	// ReviewStatusUnreviewed marks an auto-imported advisory, typically
	// module-level only.
	ReviewStatusUnreviewed ReviewStatus = "UNREVIEWED"
)

// stdlibModule and toolchainModule are the pseudo-module names the Go database
// uses for the standard library and the toolchain, respectively.
const (
	stdlibModule    = "stdlib"
	toolchainModule = "toolchain"
)

// IsWithdrawn reports whether the advisory has been retracted and must not
// produce findings.
func (e *Entry) IsWithdrawn() bool {
	return e.Withdrawn != nil
}

// ReviewStatus reports the advisory's triage status, defaulting to reviewed
// when unset (the database's own default when the field is absent).
func (e *Entry) ReviewStatus() ReviewStatus {
	if e.DatabaseSpecific == nil || e.DatabaseSpecific.ReviewStatus == "" {
		return ReviewStatusReviewed
	}
	return ReviewStatus(e.DatabaseSpecific.ReviewStatus)
}
