# Design: scalable checking (P3)

Status: proposed. Gate: land after the P1 benchmarks exist so every step is
measured.

## Problem

`CheckDetailed` today:

1. Enumerates **all simple paths** from the callgraph root to every sink
   call site (`findAllSinkCallSitePaths`): the DFS removes nodes from the
   visited set on unwind, so diamond-shaped callgraphs (N handlers → shared
   helpers → sink) produce path counts exponential in depth.
2. Re-runs that full-graph enumeration **once per sink rule**.
3. Runs an independent backward SSA walk per enumerated path, cloning the
   visited set per branch, then dedupes nearly all of that work away to one
   diagnostic per (sink position, source).
4. The memory model re-derives per-function store/load effects on every
   query with no cross-path cache.

gosec hit the same wall ("taint analysis hang on packages with many CHA
call graph edges", v2.25.0 release notes). govulncheck avoids it by never
walking whole graphs: CHA seed → forward slice from entry points → VTA →
re-slice → VTA again, then backward slicing from vulnerable symbols
intersected with the forward-reachable set.

## Proposed architecture

**One traversal, all rules.** Scan callgraph edges once, collecting sink
call sites for every sink rule simultaneously (edge → matching rules map).
This removes the per-rule multiplier.

**Per-callsite verdicts, not per-path.** For each sink call site, answer
"does any selected argument derive from a source?" once. The backward walk
already resolves parameters through the caller edge; generalize it to
consult the set of incoming edges at each parameter rather than one
materialized path. A verdict needs a witness path only when reported.

**Lazy witness paths.** Materialize a single richest witness path per
(sink, source) diagnostic after the verdict, via backward reachability from
the sink node — an `iter.Seq[Path]` with explicit depth and count caps
instead of eager `Paths` slices.

**Memoized function summaries.** Cache per-function taint transfer facts —
`map[*ssa.Function]summary` where a summary records which parameters flow
to which returns/receiver/stores, which the return-value inlining and the
memory model both re-derive today. Design the summary type to be
gob-serializable from day one: it later doubles as a go/analysis Fact for a
per-package driver mode (the only realistic golangci-lint integration).

**Visited sets push/pop, not clone.** The DFS walkers clone `seen` maps per
recursion frame; identical path-scoped semantics come from insert-before /
delete-after on one map.

**Rule matching by key, not string building.** Compute the callee string
once per edge and look it up in prebuilt maps; today each probe rebuilds
`fn.String()` and two `fmt.Sprintf` per rule (~120 propagator rules per
call site).

## What stays

The evidence-trail diagnostics API (`CheckDetailed`, `Evidence`,
deterministic ordering) is the product surface; this is an internals
rework. Depth caps (recursion 6, summary 8) remain as backstops but should
rarely bind once enumeration is per-callsite.

## Risks

- Parameter resolution currently leans on the active path for
  caller-argument mapping; per-callsite mode must join over incoming edges
  without reintroducing the over-tainting the 2026-06 precision work
  removed. The eval snapshots and detector suites are the guard.
- Witness paths must stay deterministic for SARIF fingerprint stability.

## Measurement

Before/after on: the diamond and many-sink benchmarks, wall-clock and peak
RSS on the eval git targets (mux, httprouter, chi, plus the CVE corpus),
and zero diagnostic drift on all snapshots except documented precision
changes.
