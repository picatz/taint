# Design: models as data (P4)

Status: first phase implemented — user-supplied models augment the built-in
rules via `taint.WithModels` / `LoadModels` / `ModelsFromPath` and a `-models`
CLI flag on every detector. See [../models.md](../models.md) for the user
guide. Remaining: porting the built-in tables to embedded model packs, and
field-level access paths. The rest of this document is the original design.

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
