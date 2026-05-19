# Precision Evaluation Harness

`cmd/taint-eval` runs the existing `sqli`, `logi`, and `xss` analyzers
against pinned local fixtures and remote repositories and compares the
output against committed JSON snapshots. The goal is to make false
positive and regression drift measurable as the engine evolves, without
adding any logic to the core analyzers.

## Subcommands

```
taint-eval list                       # show targets and expected counts
taint-eval check                      # fail on snapshot drift
taint-eval check -target local        # local fixtures only (no network)
taint-eval check -target <name>       # one target by name
taint-eval update -target <name>      # rewrite a snapshot after review
```

Flags:

- `-manifest` path to manifest (default `testdata/eval/targets.yaml`)
- `-snapshots` snapshot directory (default `testdata/eval/snapshots`)
- `-cache` cache root for cloned git targets (default `.cache/taint-eval`
  or `$TAINT_EVAL_CACHE`)
- `-target` target name, `local`, or `git`
- `-repo` path to the taint repo (default working directory)

## Layout

```
testdata/eval/
  targets.yaml                 # manifest of fixtures and pinned repos
  fixtures/                    # self-contained Go modules
    local-clean/
    local-sqli-positive/
    local-logi-positive/
    local-xss-positive/
  snapshots/                   # JSON expected output per target
    local-*.json
    gorilla-mux.json
    julienschmidt-httprouter.json
```

Each fixture is a complete Go module. They live under `testdata/` so the
parent `go test ./...` and `go build ./...` ignore them; the harness loads
them on demand using its own subprocess invocations.

## Snapshot semantics

Snapshots record per-analyzer findings as `(file, line, column, message)`
tuples. `file` is stored relative to the target repo root so snapshots are
machine independent. Findings outside the target tree (stdlib, module
cache) are dropped during normalization.

`check` reports two kinds of drift:

- **missing** — present in the snapshot, not produced this run
- **unexpected** — produced this run, not in the snapshot

Either drift causes a non-zero exit. When no snapshot exists yet, `check`
prints the fresh output and exits non-zero so the user has to opt in to
the baseline by running `update`.

## Determinism

The harness assumes the analyzers are deterministic: running them twice
on identical inputs must produce byte-identical JSON. This was not true
when the harness was first written — the `xss` analyzer's output for
`go-chi/chi` flapped across runs because:

1. Call graph construction iterated `map[*ssa.Function]bool` during
   prepass, appending edges to `node.Out` in random order.
2. `xss.userCallsiteForContainer` iterated `cg.Nodes` (a map) and
   reported the first matching in-package edge — different "first"
   on each run when a helper had many call sites.
3. `taint.newRuleRegistry` iterated source/sink sets to build the rule
   slices, so rule processing order varied.

These are fixed:

- `callgraphutil.Canonicalize` sorts every `node.Out` and `node.In` by
  `(site position, callee identity, callee position)` once construction
  finishes. `NewGraph` and `CreateMultiRootCallGraph` both call it.
- `xss.userCallsiteOnPath` picks the edge **on this taint path**, one
  step before the sink — not an arbitrary call to the same helper
  elsewhere in the package.
- `taint.newRuleRegistry` sorts the rule slices by id.
- `CheckDetailed` drains its dedup map in sorted-key order and uses
  `sort.SliceStable` with a total-order comparator.
- Harness normalization dedupes `(file, line, col, message)` so package
  test variants don't double-count.

Regression tests guard the invariants:

- `callgraphutil.TestCallgraphEdgeOrderingIsCanonical`
- `callgraphutil.TestCallgraphIsDeterministicAcrossBuilds`
- `xss.TestDeterminism` (10 iterations against a chi-style fixture)

## Manual CI

A `workflow_dispatch`-only GitHub Actions workflow lives at
`.github/workflows/precision-eval.yml`. It is not on the default PR path;
operators trigger it manually before a release or after analyzer
changes. The same workflow can be re-run locally with:

```
go install ./cmd/taint-eval
taint-eval check          # all targets, parallel by default
taint-eval check -jobs 4  # tune concurrency
taint-eval check -target local   # local fixtures only
```

`go run ./cmd/taint-eval ...` works too but rebuilds the harness each
invocation, which dominates the wall-clock cost of short iteration
loops.
