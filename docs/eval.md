# Precision Evaluation Harness

`cmd/taint-eval` runs the existing `sqli`, `logi`, `cmdi`, `xss`, `ptrv`,
and `ssrf` analyzers against pinned local fixtures and remote repositories.
It measures two different things, without adding any logic to the core
analyzers:

- **Drift** (`check`) — compares output against committed JSON snapshots
  so false-positive and regression drift surface as a diff. A snapshot is
  purely descriptive: it baselines *whatever the engine currently emits*,
  including any false positives.
- **Ground truth** (`report`) — scores output against `expect` entries in
  the manifest, which record *known-vulnerable sinks* independent of what
  the engine does. This yields per-analyzer precision and recall.

## Drift vs ground truth

The two models are deliberately separate and can disagree:

| | Snapshot (`check`) | Expectation (`report`) |
|---|---|---|
| Records | what the engine emits today | what is actually vulnerable |
| Source | `taint-eval update` | hand-authored `expect:` in `targets.yaml` |
| A false positive is | baselined (so `check` stays green) | counted as FP against ground truth |
| A missed CVE is | invisible (nothing to baseline) | counted as FN (recall < 1) |
| Failure mode | drift from baseline → non-zero exit | never fails on the numbers |

Concretely: `go-chi-chi` has a snapshot recording one `xss` finding at
`mux.go:506`. `check` treats it as the expected baseline and passes; but
because chi carries no `expect` entry claiming that line is vulnerable,
`report` counts it as a false positive. Conversely the CVE targets have
`expect` entries the engine does not yet find, so `report` counts them as
false negatives while `check` stays green (their snapshots are empty).

## Subcommands

```
taint-eval list                       # show targets and expected counts
taint-eval check                      # fail on snapshot drift
taint-eval check -target local        # local fixtures only (no network)
taint-eval check -target <name>       # one target by name
taint-eval report                     # precision/recall vs ground truth
taint-eval report -target local       # score local fixtures only
taint-eval update -target <name>      # rewrite a snapshot after review
```

Flags:

- `-manifest` path to manifest (default `testdata/eval/targets.yaml`)
- `-snapshots` snapshot directory (default `testdata/eval/snapshots`)
- `-cache` cache root for cloned git targets (default `.cache/taint-eval`
  or `$TAINT_EVAL_CACHE`)
- `-target` target name, `local`, or `git`
- `-repo` path to the taint repo (default working directory)
- `-sarif-dir` optional directory for per target/analyzer SARIF reports
- `-jobs` max concurrent target evaluations

## Layout

```
testdata/eval/
  targets.yaml                 # manifest of fixtures and pinned repos
  fixtures/                    # self-contained Go modules
    local-clean/
    local-sqli-positive/
    local-logi-positive/
    local-cmdi-positive/
    local-xss-positive/
    local-ptrv-positive/
    local-ssrf-positive/
  snapshots/                   # JSON expected output per target
    local-*.json
    gorilla-mux.json
    julienschmidt-httprouter.json
    go-chi-chi.json
    <cve-target>.json          # known-vulnerable repos (see below)
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

## Ground-truth format

A target may carry `expect` entries: hand-authored ground truth recording
sinks that *should* be reported, regardless of whether the engine finds
them today. Each entry is:

```yaml
expect:
  - analyzer: sqli          # required; must be one of the target's analyzers
    file: object/adapter.go # required; path relative to target root, forward slashes
    line: 198               # optional; 0 (omitted) matches any line in file
    note: CVE-2022-24124 …  # optional; CVE/advisory reference or rationale
```

Matching rule: an actual finding satisfies an entry when the analyzer and
file match and either `line` is 0 or the lines match. Use `line: 0` (omit
`line`) when the exact reporting position is unstable but the vulnerable
file is known, and a pinned line when you want to detect the engine
reporting the *wrong* place in the right file.

`report` folds each run into three buckets per analyzer:

- **TP** (true positive) — an `expect` entry matched by ≥1 finding
- **FN** (false negative) — an `expect` entry no finding matched
- **FP** (false positive) — a finding not explained by any `expect` entry

From these it prints `precision = TP/(TP+FP)` and `recall = TP/(TP+FN)`,
or `n/a` when the denominator is zero (no positives / no expectations).
`report` never exits non-zero on the numbers — a 0-recall row on a real
CVE is valuable data, not a failure. Only infrastructure problems (clone,
build, package load) fail the command.

## Adding a CVE target

1. Find the vulnerable release and the exact sink. The advisory (GHSA/CVE)
   usually links the fix commit or the vulnerable file+line; pin the
   *vulnerable* commit, not the fix.
2. Add a `git` target to `targets.yaml`. Scope `packages` to the subtree
   holding the vulnerable flow (e.g. `./internal/ssh`) — loading a whole
   large application per package is slow and memory-hungry, and the engine
   analyzes per package regardless.
3. Verify it loads under the local Go toolchain **before** committing:
   `go run ./cmd/taint-eval report -target <name>`. If packages fail to
   typecheck, drop the target (or narrow `packages`) and note why. Test-
   augmented package variants that fail to compile are tolerated — the
   harness records them as warnings and keeps the healthy package.
4. Add `expect` entries for the known sink(s) with a `note` citing the
   advisory. Then `taint-eval update -target <name>` writes the snapshot
   (typically empty findings — that is the honest baseline) so `check`
   stays green.

Clones land in `.cache/taint-eval` (gitignored), keyed by host/owner/name
and short commit.

## Scoreboard

Initial numbers from `taint-eval report` (Go 1.26, all targets). The CVE
targets are pinned to vulnerable releases; the engine finds none of their
published sinks yet, which is in line with reported single-tool CVE recall
(≈11–27%). This is recorded reality, not a tuning target.

```
ANALYZER  TP  FN  FP  PRECISION  RECALL
cmdi      1   2   0   1.00       0.33
logi      1   0   0   1.00       1.00
ptrv      1   0   0   1.00       1.00
sqli      1   5   0   1.00       0.17
ssrf      1   0   0   1.00       1.00
xss       1   0   1   0.50       1.00
TOTAL     6   7   1   0.86       0.46
```

Reading the rows:

- Every analyzer scores 1 TP from its local positive fixture, so the
  smoke-test recall floor is intact.
- `sqli` and `cmdi` FNs are the CVE sinks the engine misses (go-dvwa,
  gogs, casdoor ×2, prest, ekuiper).
- The single `xss` FP is `go-chi-chi` `mux.go:506` — a pre-existing
  false positive that predates the sink-arg selector precision work
  (commits `ff19048..ac0add5`) and is baselined in the snapshot.

Pinned CVE targets (all load + typecheck under Go 1.26):

| Target | Ref | Class | Recall |
|---|---|---|---|
| `sqreen-go-dvwa` | master `822f4bf` | SQLi + cmdi | 0/2 |
| `gogs-cve-2024-39930` | v0.13.0 | cmdi (arg injection) | 0/1 |
| `casdoor-cve-2022-24124` | v1.13.0 | SQLi | 0/2 |
| `prest-ghsa-p46v-f2x8-qp98` | v2.0.0-rc2 | SQLi | 0/1 |
| `ekuiper-ghsa-r5ph-4jxm-6j9p` | v1.14.0 | SQLi | 0/1 |

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
changes. It runs `check` (drift gate) and then `report` (informational
scoreboard; `report` never fails on the numbers, so it does not gate the
workflow beyond surfacing package-load failures). The same workflow can
be re-run locally with:

```
go install ./cmd/taint-eval
taint-eval check          # all targets, parallel by default
taint-eval check -jobs 4  # tune concurrency
taint-eval check -target local   # local fixtures only
taint-eval report         # precision/recall scoreboard
```

`go run ./cmd/taint-eval ...` works too but rebuilds the harness each
invocation, which dominates the wall-clock cost of short iteration
loops.
