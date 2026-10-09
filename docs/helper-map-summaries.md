# Helper-map summary reduction

Map lookups can use statically resolved helper writes and kills. The summary
reducer now aggregates those already-discovered events with an explicit,
query-local DFS instead of enumerating backward CFG paths. A chain of N
independent diamonds has 2^N paths, although it may contribute only one value.
The reducer does not impose a path cap or truncate candidate values.

## Compatibility contract

The output remains the stable ordered union of effects from the old path
collector. Each effect is deduplicated by value, call, callee, and definite flag
**before** caller metadata is remapped and writes are weakened. Return order,
reverse instruction order, predecessor order, and event order within one
instruction are preserved.

A definite kill stops predecessor traversal after every event at that instruction
has been processed. Definite writes retain their existing weak summary behavior.
The initial cursor before a return is distinct from a loop revisit at the end of
the same block. Gray DFS edges represent the old un-killed cycle cutoff; black
edges are shared suffixes whose contributions have already been processed.

The all-path kill result is true exactly when the kill-truncated reachable cursor
graph has neither an un-killed terminal nor a cycle. First visits retain the old
flattened output's first occurrences: every encountered effect contributes to a
terminal path state, and repeated suffix visits introduce no new first occurrence.
All storage is query-local. There is no global cache retaining SSA functions.

## Work bound and limits

Let R be the number of returns, I the helper's instruction count, E its
predecessor-edge count, and F the number of input event/value entries. For the
already-built events, indexing plus reduction costs expected O(R*(I+E+F)) time
and O(I+E+F) space, with hash-map operations taken as expected constant time.
This expression assumes ordinary SSA, where every block has an instruction.
For arbitrary synthetic graphs with empty blocks, include the block count B:
expected O(F + R*(B+I+E+F)) time. Live auxiliary/output storage is O(B+F);
this is not a hard Go heap/RSS cap or cumulative allocation bound. Each return
has at most one end cursor per block plus its initial before-return cursor.
No instruction or edge is traversed once per CFG path.

This is a bound on reduction only, not the entire helper query or analyzer.
Finding events still scans helper instructions, resolves arguments/constants,
performs map-alias and type-related work, and expands nested static calls up to
the configured depth. The cost of those operations depends on their own input
sizes and algorithms; depth bounds do not imply a linear nested-call expansion.
Callgraph construction/path selection and other memory models are unchanged.

The change deliberately preserves current precision behavior. In particular,
nested conditional clear/delete effects still lose control-flow information
before reduction, and nested write-then-delete effects still lose instruction
ordering. Tests explicitly record these inherited false negatives/positives
alongside their semantic expectations. This performance change does not extend
helper handling to map ranges, general aliases, globals, or concurrency.

## Verification and reproduction

The legacy collector exists only in a bounded test oracle. Differential coverage
includes 10,000 fixed-seed abstract CFG/event cases, cycles, joins, duplicate
edges, mixed metadata, multiple events at an instruction, and valid SSA fixtures
with branches, loops, early returns, switches, gotos, and nested calls. A separate
64-diamond production-only test verifies that no path list is materialized.

Run focused coverage and allocation benchmarks with:

```sh
go test -run '^TestHelperMap' -count=1 .
go test -run '^$' -bench '^BenchmarkHelperMap' -benchmem -benchtime=1x -count=3 .
```

`BenchmarkHelperMapSummary` includes event discovery and reduction, excluding
SSA construction. `BenchmarkHelperMapCollectorReduction` compares old and new
reduction including event indexing, excluding event discovery. Fixture setup and
output comparisons are outside the timed loops. Report these scopes separately;
shared-host timings are not reliable evidence of throughput speedup.

## Selected-key correctness

The finite reducer remains unchanged. Selected map-key matching now preserves
concrete interface key types and resolves key parameter wrappers separately from
value summaries. See [selected map-key identity](map-key-identity.md) for supported
conversions and remaining conservative boundaries. This does not repair the
nested control-flow limitations described above.
