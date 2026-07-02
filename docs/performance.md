# Performance Benchmarks

`bench_test.go` benchmarks `CheckDetailed` (`check.go`) directly, at the
package level, on synthetic callgraphs generated on the fly with
`strings.Builder` (no fixtures under `testdata/`). It exists to quantify the
path-explosion cost identified in
[`docs/design/scalable-checking.md`](design/scalable-checking.md) *before*
that rework lands, so every optimization step can be measured against a real
baseline instead of a guess.

Each benchmark builds its SSA callgraph once, outside the timed loop (the
same `packages.Load` → `ssautil.Packages(ssa.InstantiateGenerics)` →
`callgraphutil.NewGraph` pipeline `check_detailed_test.go` uses, duplicated
into a self-contained `buildBenchCallGraph` helper), then times only the
`CheckDetailed` call itself via `for b.Loop()` (Go 1.24+).

## Running

```
go test -run=^$ -bench=. -benchmem .
```

Run one shape at a time, or a single sub-benchmark, with the standard `-bench`
regexp:

```
go test -run=^$ -bench=BenchmarkCheckDetailedLinear    -benchmem .
go test -run=^$ -bench=BenchmarkCheckDetailedDiamond   -benchmem .
go test -run=^$ -bench=BenchmarkCheckDetailedManySinks -benchmem .
go test -run=^$ -bench=BenchmarkCheckDetailedManyDiagnostics -benchmem .
```

At small `-benchtime` values (few iterations) `sec/op` is noisy on a loaded
laptop; `B/op` and `allocs/op` are deterministic for these benchmarks (no
randomized iteration or timing-dependent branches in `CheckDetailed`'s hot
path) and are the more reliable signal run-to-run. For a stable read, or
before/after comparisons while working on the P3 rework, use `-count` and
[`benchstat`](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat):

```
go test -run=^$ -bench=BenchmarkCheckDetailedDiamond -benchmem -count=10 . > new.txt
benchstat old.txt new.txt
```

`golang.org/x/perf/cmd/benchstat` is not vendored into this module; install
it once with `go install golang.org/x/perf/cmd/benchstat@latest`.

The diamond benchmark also reports a custom `paths` metric — the exact number
of simple root-to-sink-callsite paths `findAllSinkCallSitePaths` enumerates
for that configuration (computed once, before the timed loop, via the same
package-internal call `CheckDetailed` makes) — so the growth curve can be read
directly off `go test -bench` output without cross-referencing formulas.

## Baseline

Machine: Apple M1 Pro (arm64), macOS (Darwin 25.5.0), Go 1.26.0. Single run,
no other load; treat absolute numbers as indicative, not authoritative —
re-run locally before drawing conclusions on different hardware.

### Linear chain (`BenchmarkCheckDetailedLinear`)

`main -> f1 -> ... -> fN -> sink`, one path regardless of depth. `-benchtime=50x -count=3`, median shown:

| depth | sec/op | B/op | allocs/op |
|---|---|---|---|
| 4  | 9.13µs  | 11.05Ki | 150 |
| 8  | 13.09µs | 18.28Ki | 245 |
| 16 | 23.21µs | 34.47Ki | 426 |

Cost grows linearly with chain depth — doubling depth roughly doubles
`allocs/op` (150 → 245 → 426, ~+95 and ~+181 per doubling, tracking depth
directly). This is the expected shape for a single backward SSA walk over a
single path: the walk itself is not the bottleneck.

### Diamond (`BenchmarkCheckDetailedDiamond`)

`width` functions per layer, every function in layer *i* calls all `width`
functions in layer *i+1*, final layer calls the sink with a threaded tainted
value — the "N handlers → shared helpers → sink" shape from the design doc.
`-benchtime=30x -count=3`, median shown:

| config (width x layers) | paths (= width^layers) | sec/op | B/op | allocs/op |
|---|---|---|---|---|
| 2x2 | 4   | 35.6µs  | 26.93Ki | 334    |
| 4x2 | 16  | 121.9µs | 102.8Ki | 1,201  |
| 8x2 | 64  | 382.2µs | 404.7Ki | 4,587  |
| 2x3 | 8   | 41.7µs  | 65.68Ki | 751    |
| 4x3 | 64  | 295.9µs | 510.4Ki | 5,491  |
| 8x3 | 512 | 3.53ms  | 3.96Mi  | 42,734 |

The `paths` metric matches `width^layers` exactly, as expected from
`findAllSinkCallSitePaths`'s unrestricted simple-path DFS over a complete
bipartite fan-out between consecutive layers. `allocs/op` tracks it closely:
holding `layers=3` fixed, doubling `width` from 4 to 8 multiplies paths by
8x (as predicted by `width^layers`) and `allocs/op` by ~7.8x (5,491 →
42,734); holding `width=8` fixed, adding a third layer multiplies paths by
8x (64 → 512) and `allocs/op` by ~9.3x (4,587 → 42,734). In both directions
measured cost growth is within ~15% of the combinatorial prediction — this
*is* the exponential-in-layers, polynomial-in-width blowup
`docs/design/scalable-checking.md` names as problem #1, reproduced here at a
scale still small enough to stay under a few milliseconds per op. Real
callgraphs commonly have wider layers and more of them (a router with 40
handlers sharing 5-deep middleware/helper chains is not unusual), so this
curve is the argument for the per-callsite verdict rework, not an alarm about
these specific tiny synthetic programs.

### Many sinks (`BenchmarkCheckDetailedManySinks`)

One fixed program, one real flow, only the `Sinks` set size (`n`) varies —
`n-1` filler rules that never match plus the one real rule. This isolates
problem #2 from the design doc: `findAllSinkCallSitePaths` re-runs a full
graph traversal once per sink rule regardless of whether that rule matches
anything. `-benchtime=50x -count=3`, median shown:

| sinks (n) | sec/op | B/op | allocs/op |
|---|---|---|---|
| 1  | 5.23µs  | 6.01Ki  | 82    |
| 4  | 15.65µs | 15.94Ki | 337   |
| 16 | 56.19µs | 57.04Ki | 1,352 |

`allocs/op` scales almost exactly linearly in `n` (82 → 337 → 1,352 is
within 3% of 82×1, 82×4.11, 82×16.5) even though 15 of the 16 rules at `n=16`
match nothing in the graph. This is the per-sink-rule re-enumeration cost the
design doc's "one traversal, all rules" proposal removes — a program with `R`
configured sink rules pays `R`x the graph-traversal cost today no matter how
many of those rules are actually relevant to it.

### Many diagnostics (`BenchmarkCheckDetailedManyDiagnostics`)

20 independent handlers, each with its own direct `source()` → `db.Query`
flow (no shared helpers, so path enumeration stays `O(20)`, not
combinatorial). `-benchtime=50x -count=3`, median shown:

| sec/op | B/op | allocs/op |
|---|---|---|
| 63.6µs | 94.7Ki | 1,130 |

For comparison, the diamond `8x2` config (64 paths collapsing into 8
diagnostics) already costs more (`382µs`, `4,587 allocs/op`) than 20 fully
independent diagnostics with zero shared structure. Diagnostic construction
and deduplication (`buildDiagnosticEvidence`, the `bestByKey` map in
`CheckDetailed`) is not the bottleneck; the shared-helper fan-out topology
that inflates path counts is.

## Interpretation

The three cost drivers `docs/design/scalable-checking.md` names are all
independently reproducible and roughly linearly separable at these sizes:

1. **Path count** grows as `width^layers` on diamond-shaped graphs — the
   dominant cost, and the one that can blow up fastest as real codebases add
   handlers or middleware layers.
2. **Sink rule count** multiplies graph-traversal cost linearly, even when
   only one rule matches anything in the program.
3. **Diagnostic volume** (many independent, non-shared flows) is comparatively
   cheap — dedup and evidence construction do not dominate.

None of the tested configurations approached the 15s/op or 2GB caps this
suite was asked to respect; the largest (`8x3` diamond, 512 paths) finished
in single-digit milliseconds and a few megabytes. That headroom is
intentional — these benchmarks are meant to establish a clean, cheap-to-run
baseline curve now, while `CheckDetailed` is still simple enough that
`width^layers` and linear-in-sink-rule-count are visible directly in
`allocs/op`, rather than to find the actual wall-clock cliff on this
machine. The design doc's own "Measurement" section calls for before/after
numbers on "the diamond and many-sink benchmarks" specifically — these are
those benchmarks, and this table is the "before."

## Test suite

`go test . -count=1` passes with `bench_test.go` present (benchmarks are not
exercised by `go test` without `-bench`, so adding them does not change
`go test`'s runtime or pass/fail status).
