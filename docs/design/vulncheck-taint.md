# Design: a taint-powered govulncheck equivalent (P6 candidate)

Status: research complete (2026-07-04), not started. This document records how
the Go vulnerability data ecosystem carries symbol information, what
govulncheck actually does, and how to build a scanner on our taint engine that
answers a strictly stronger question than govulncheck: not "is a vulnerable
symbol reachable" but "does attacker-controlled data reach it".

## The pitch

govulncheck's own documentation concedes its ceiling: it proves a static call
path exists, not that the vulnerability is exploitable. Its known criticisms
are conservative interface dispatch (VTA fan-out on `io.Writer`/`error`),
reflection blind spots, and "reachable is not exploitable" noise. We already
have the two ingredients it lacks: a whole-program taint engine with
explainable `CheckDetailed` evidence, and the exact same CHA+VTA callgraph
builder it uses (`callgraphutil/graph_vulncheck.go`, ported January 2024).

The product shape is a tiered scanner (working name: `taint vuln` command or
`cmd/vulncheck`):

| Tier | Question | Mechanism | DB coverage |
|---|---|---|---|
| module | is a dependency in a vulnerable version range | go.mod / build list vs SEMVER ranges | 100% (3,786 entries) |
| package | is the vulnerable package imported | import graph | ~21% (801 entries with `imports`) |
| symbol | is a vulnerable symbol reachable | VTA callgraph (govulncheck parity) | ~20% (740 entries with symbols) |
| taint | does tainted data reach the vulnerable symbol | advisory symbols compiled into sink rules + `CheckDetailed` | same ~20%, prioritized |

Each finding reports the highest tier it reaches. The taint tier is the
differentiator: a `tainted-reachable` finding means untrusted input flows into
the vulnerable call's arguments, with the engine's evidence chain attached.
A `reachable-but-clean` verdict is also valuable signal (deprioritize), while
never claiming safety (taint analysis misses flows; reachability stands).

## What the data actually looks like (measured 2026-06-26 snapshot)

- 3,786 OSV entries at vuln.go.dev; 969 REVIEWED, 2,817 UNREVIEWED, 9 withdrawn.
- 2,985 (79%) have NO `ecosystem_specific.imports` at all: module-level only.
  Essentially all UNREVIEWED entries are this shape (auto-imported, often
  `introduced: "0"`, no packages, no symbols).
- 740 entries carry symbols (76% of REVIEWED). Median 4 symbols, mean 11.7,
  max 262. 61 more have packages but zero symbols (package-level, "any call
  into the package counts", and per spec any *import* marks the program
  vulnerable).
- Only 33 entries carry goos/goarch constraints. 157 affect `stdlib`,
  30 `toolchain` (those are pseudo module names in OSV; YAML uses `std`/`cmd`).
- Symbol spelling: package-relative `Func` or `Recv.Method`, pointer star
  STRIPPED (`B.bar`, never `(*B).bar`), type params omitted, unexported
  allowed (e.g. `p256SubInternal`).
- `symbols` vs `derived_symbols` exist only in the vulndb YAML. OSV flattens
  them into one list, so consumers cannot tell root causes from the derived
  exported closure. The derivation is the same VTA callgraph govulncheck
  uses, run at the module's `vulnerable_at` version: derived = exported entry
  points of the vulnerable package(s) from which a root symbol is reachable,
  minus `init`, minus human-vetoed `excluded_symbols` (also unpublished).
  The public `golang.org/x/vulndb/report` package can parse the YAML if we
  ever want root-vs-derived separation (the taint tier arguably should target
  ROOT symbols: "does tainted data reach the root cause through any path").
- `data/excluded/` reports (834) are not published to vuln.go.dev at all.
- The `index/vulns.json` entries do NOT carry `withdrawn`; the full record
  must be read to skip the 9 withdrawn entries.

## Data pipeline decision

Skip both official binding modules:

- `github.com/ossf/osv-schema/bindings/go/osvschema` became protobuf-generated
  in October 2025 (`structpb.Struct` for `ecosystem_specific`, requires
  `protojson.Unmarshal`, drags grpc/protobuf deps) and has no semver tags.
- `osv.dev/bindings/go/osvdev` only adds server-side version matching, returns
  GO-* and GHSA-* duplicates that need alias dedup, and its querybatch returns
  IDs only (each needs hydration).

Instead: fetch `https://vuln.go.dev/vulndb.zip` (2.8 MB, whole database, plain
static files, no key) or incremental via `index/db.json` (modified stamp) +
`index/modules.json` (module -> vuln IDs + latest-fixed prefilter) +
`ID/GO-*.json`. Define our own ~40 lines of structs including:

```go
type goEcosystemSpecific struct {
    Imports []goImport `json:"imports,omitempty"`
}
type goImport struct {
    Path    string   `json:"path"`
    GOOS    []string `json:"goos,omitempty"`
    GOARCH  []string `json:"goarch,omitempty"`
    Symbols []string `json:"symbols,omitempty"` // empty = whole package
}
```

Version matching is local: Go uses only SEMVER ranges, unprefixed
(`"1.9.1"`), so prepend `"v"` and use `golang.org/x/mod/semver`. Affected iff
`introduced <= v < fixed` in some event pair; missing introduced means `"0"`;
stdlib ranges use `1.N.0-0` prerelease sentinels (strip the `go` prefix from
toolchain versions before comparing). Respect `withdrawn` and surface
`database_specific.review_status`.

## Matching advisory symbols to the engine

Advisory `Recv.Method` (no star, package-relative) fans out to both receiver
spellings in our fully qualified sink-id format:

- `Parse` in `golang.org/x/text/language` -> `golang.org/x/text/language.Parse`
- `Conn.Query` in pkg `p` -> `(p.Conn).Query` AND `(*p.Conn).Query`

Empty symbol list widens to every function in the package (govulncheck
semantics). These compile into dynamic sink rules exactly like models-as-data
sinks (`kind: GO-2021-0113`), no engine changes needed for the matching
itself; `edgeCallsSink` already matches fully qualified ids per call edge.

## The callgraph substrate is current (verified)

Our January 2024 port of govulncheck's callgraph was diffed against x/vuln
master: the algorithm is unchanged (CHA seed -> forward slice from entries ->
VTA -> re-slice -> VTA -> DeleteSyntheticNodes, exactly two VTA rounds; the
forwardSlice body is identical). The single upstream change (September 2024)
removed `ssautil.AllFunctions` and both `pruneSet` calls as redundant work.
Action: mirror that deletion (harmless perf win), and confirm our SSA build
for this path sets `ssa.InstantiateGenerics` (VTA requires it; govulncheck
builds with exactly that one flag). Entry-point selection to mirror: for main
packages only `main` + `init*`; for library scans, exported non-synthetic
functions plus package initializers.

## Output format

The govulncheck streaming JSON format is the interchange contract: osv-scanner
shells out to govulncheck and decodes it with copied structs; gopls vendors a
fork; CI actions re-emit SARIF from it. The types live in
`internal/govulncheck` (not importable) but are BSD-licensed, small, and
protocol-versioned: copy `Message{Config|Progress|OSV|Finding}`,
`Finding{OSV, FixedVersion, Trace []*Frame}`,
`Frame{Module, Version, Package, Function, Receiver, Position}`. Finding tier
is encoded by the deepest populated frame (module-only, +package, +symbol).
Our taint tier rides either as an extension field or as our own SARIF
enrichment (we already have SARIF plumbing in `internal/analyzercmd`); exact
encoding TBD when implementing.

## Phasing

1. **`vulndb` package + module tier.** Zip/index client with local cache and
   `modified`-based refresh, own OSV structs, semver matching, withdrawn/
   review-status handling, alias (CVE/GHSA) lookup. CLI: scan go.mod/build
   list, report module-tier findings. No SSA; fast; covers the whole DB.
   Test against pinned fixtures (GO-2021-0113, GO-2022-0187, GO-2025-3361
   cover the three data shapes).
2. **Package + symbol tiers.** Import-graph matching; then VTA reachability
   using the refreshed builder, symbol-spelling adapter, govulncheck-style
   entry points. Parity target: same symbol-level findings as govulncheck on
   the eval corpus repos (they are pinned at vulnerable versions and several
   have GO- advisories with symbols: gogs, casdoor, prest, ekuiper).
3. **Taint tier.** Compile matched advisories' symbols into sink rules, run
   `CheckDetailed` with the built-in source sets (plus models), and emit
   `tainted-reachable` findings with evidence chains. Scope control: only
   run taint for advisories that already passed symbol reachability (small
   sink sets, bounded work). Evaluate on the eval corpus: how many known-CVE
   targets does the taint tier confirm vs reachability alone.
4. **Distribution.** govulncheck-compatible `-json` stream, SARIF, GitHub
   Action wiring. Binary mode: out of scope (no callgraph, no taint value;
   govulncheck already covers it).

## Risks and open questions

- **Performance.** Whole-program SSA + 2x VTA is govulncheck's documented
  bottleneck (multi-minute on large repos); our taint path enumeration is
  costlier still. Mitigated by tiering (taint only on reachability hits) but
  the P3 engine-scalability work (per-callsite analysis, summary memoization)
  remains the real fix. Do not block on it; measure on the eval corpus.
- **Source model for libraries.** A library scan has no `main`; govulncheck
  treats exported functions as entries. For the taint tier the analogue is
  treating exported-function parameters as sources (the engine's existing
  entrypoint fallback via `matchSourceType`), which over-taints; acceptable
  for a prioritization signal, needs wording care in output.
- **Coverage honesty.** The taint tier applies to the ~20% of advisories with
  symbols (roughly the fraction that matters for reachability too). Output
  must degrade loudly, never silently: module-tier findings say "update
  regardless", symbol-tier says "reachable", taint-tier says "reachable with
  untrusted data".
- **Taint semantics per advisory class.** v1 treats "any tainted data reaching
  any argument of the vulnerable symbol" as the signal. Some CVE classes
  (e.g. a DoS in a decoder) genuinely fire on any input; others (SSRF in a
  client) hinge on a specific argument. The vulndb YAML has no per-argument
  data, so refinement would be our own curated overlay (models-as-data files
  keyed by OSV id), a natural extension of the existing models format.
- **stdlib/toolchain vulns.** Module tier needs the Go version (from go.mod
  `go`/`toolchain` directives or `runtime.Version()` of the scan target);
  symbol tier works unchanged for stdlib call targets; `toolchain` entries
  are version-only by nature.
