# Design: models as data (P4)

Status: implemented for user-supplied models. Models augment the built-in
rules via `taint.WithModels` / `LoadModels` / `ModelsFromPath`, a `-models`
CLI flag on every detector, and a `models` command in the interactive tool.
Argument selectors support indices, ranges, `receiver`, and the CodeQL
`Argument[...]` spellings; a trailing field access (`Argument[0].Field[f]`) is
field-sensitive for sinks, while element access still resolves to the whole
argument. Packs can be embedded via `//go:embed` + `LoadModels(fs.FS)`. See
[../models.md](../models.md).

Built-in-table migration (done for detectors): **all six detectors** —
`sqli`, `logi`, `cmdi`, `xss`, `ptrv`, `ssrf` — now load their sources, sinks,
and (where it coincides with the sink packages) their import gate from an
embedded pack next to the detector, instead of Go tables. Each is proven by
its analysistest suite; the large `sqli`/`logi` packs were generated from the
existing sink lists so the transcription is exact.

To avoid duplicating selector logic, a model sink with no `args`/`select`
inherits the engine's built-in selector for its method id (the `exactSinkRule`
switch remains the single source of truth for standard-library sinks, and
still serves direct `NewSinks` callers). Custom selectors that positional
indices cannot express are exposed as named selectors (`select: http-post-url`,
etc.), reusable from user models. Detectors whose import gate is broader than
their sink packages (`xss` triggers only on `net/http`; `sqli` also triggers
on the `go-sqlite3` driver) keep an explicit gate; the constant-query
post-filter in `sqli` stays in Go.

The shared propagator table is also embedded now
(`builtin/propagators.yaml`), generated from the Go table.

Field-level flow (first phase): sources are now field-sensitive — a
`SourceModel` with a `field` taints only accesses to that struct field, and
the FieldAddr walk skips sibling-field referrers when a field-source applies
to the base type, so one field's taint does not leak into another.

Field taint through stores is now field-precise for **globals** as well:
the reaching-store search for a package-level variable compares the load's
field/index path against each store's path (`globalStoreMatchesLoad` +
`addrStepsPrefixAlias`), so writing `G.A` no longer taints a read of `G.B`.
The comparison uses prefix-aliasing (a whole-object access overlaps any field,
a parent-field write overlaps a nested-field read, siblings never overlap) and
falls back to matching whenever either path is unresolved or an index is
non-constant, so the change only ever removes false positives — it never drops
a legitimate flow. Local scalar stores were already field-distinct via SSA
registers, and cross-procedure helper stores already used this comparator; this
closes the remaining coarse case.

Field-sensitive sinks are now supported too: a sink `args` selector with a
field access (`Argument[0].Field[Message]` or the shorthand `0.Field[Message]`)
fires only when that struct field of the argument is the tainted channel. The
sink check resolves the field precisely for the common shapes (a struct built
and passed by value or pointer, returned from an analyzable helper, or threaded
through parameters — `checkFieldOfValueTainted`), and falls back to the whole
value for shapes it cannot resolve, so it never under-reports relative to a
non-field-sensitive sink. This also added the by-value `*ssa.Field` case to the
walk, closing a latent gap where a field-source read out of a struct *value*
(rather than through its address) was not recognized.

Remaining here: field-sensitive summaries (argument access paths into fields),
cross-procedure field stores into a sink argument, and field precision for
buffered writes. The rest of this document is the original design.

## Problem

Source, sink, propagator, and sanitizer knowledge is hardcoded Go: ~120
propagator rules in `rules.go`, per-detector sink lists in each analyzer
package. Growing coverage is a code change and a release (issues #3 and
#7 are both really this problem). Users can already pass custom
`NewSources`/`NewSinks` through the library API, but CLI users get fixed
lists, and there is no way to model third-party framework *flow* (a
function summary) without editing the engine.

CodeQL's models-as-data is the reference design: extensible YAML rows for
`sourceModel`/`sinkModel`/`summaryModel` with a compact access-path grammar
(`Argument[0]`, `Argument[receiver]`, `ReturnValue[1]`, ranges), a
taint-vs-value kind, and per-package grouping. go-flow-levee (archived
2026-04) proved the YAML-config approach for Go; Argot ships one config
schema across all its analyses.

## Proposed format

One YAML document per modeled package, embedded via `embed.FS`, loadable
from user-supplied directories too:

```yaml
package: database/sql
sinks:
  - method: (*DB).Query        # resolved against the package path
    args: [0]                  # positional sink arguments
    kind: sql-injection
  - method: (*DB).QueryContext
    args: [1]
    kind: sql-injection
sources:
  - type: "*net/http.Request"  # fully qualified when cross-package
summaries:
  - func: strings.Join
    flow: { from: "Argument[0..1]", to: ReturnValue, kind: taint }
sanitizers:
  - func: html.EscapeString
    kind: xss
```

Compilation target is the existing internal `ruleRegistry`
(`sourceRule`/`sinkRule`/`propagatorRule`/`sanitizerRule`); the engine does
not change, only where rules come from. `args` subsumes the hand-written
`selectArgs` closures for the common positional case; genuinely custom
selectors (shell `-c` detection) stay in Go and are referenced by name.

## Import-aware loading

Only load model packs for packages the target program actually imports
(plus stdlib packs). This is the "contextual support" both #3 and #7 asked
for: coverage growth stops costing every user matching time, and adding a
framework becomes adding a file.

## Migration

1. Loader + schema validation + `embed.FS` packs, compiled into the
   registry behind the existing detector APIs (no behavior change).
2. Port the hardcoded tables pack by pack, each ported pack proven by the
   existing analysistest suites.
3. CLI flag (`-models dir/`) for user packs; document the format.
4. Then close #3/#7: remaining coverage requests become model-pack PRs
   that touch no engine code.

## Non-goals (for this phase)

Field-level access paths (`Argument[0].Field[q]`) and flow states are
deferred; the schema reserves room (access-path strings, `kind`) so they
can be added without a format break.
