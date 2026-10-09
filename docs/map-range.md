# Map range propagation

Map iteration produces `(ok, key, value)` in SSA. The checker follows only the
selected key or value component; iteration status is never data taint. A tainted
key does not contaminate a clean value, or vice versa.

For writes in the same function, the engine follows each candidate entry to the
iterator's `Next` instruction. A definite same-map, constant-key overwrite or
`delete` kills that entry; `clear` kills all previous entries on that path. A
conditional kill leaves other paths open. Different entries stay independent.
Identical SSA keys also prove equality for reflexive key types (such as strings)
while their defining instruction has not been reexecuted on the candidate path.
Otherwise dynamic keys are weak updates. Floating-point NaNs, including NaNs
inside arrays, structs, or interfaces, must not be assumed equal to themselves.

The range expression fixes the map identity, but does not snapshot its contents.
Go's [map iteration order is unspecified](https://go.dev/ref/spec#For_range):
entries added during iteration may be visited, and a tainted entry can be visited
before a later deletion. A write in the loop body can therefore reach a later
`Next` through a backedge. Writes after the loop, or after an extraction followed
by an unconditional break, cannot taint that already-extracted scalar value.
Deleting or clearing after extraction likewise cannot clean a scalar copy.
Reexecuting a loop-local map allocation starts a fresh map.

## Scope and precision limits

This model covers direct same-function map updates, representation-preserving
conversions, and possible aliases through Phi joins. Possible aliases can
contribute writes, but do not establish definite kills of every alternative.
It does not infer iteration order, correlate key tests with entries already
visited, or prove general branch conditions. For example, updating the entry
currently being visited can conservatively flow to a later iteration even though
that entry will not be visited again. Such correlations may produce false
positives. Pointer-valued keys and elements are not immutable copies of the pointed-to
contents. Directly dereferenced pointers to entry-block local allocations use
the actual dereference position, with a finite backward walk over local stores.
A closed-use guard rejects helpers, closures, pointer Phi joins, lookups, other
pointer extractions, and container escapes; those cases retain the existing
pointee analysis. Four inherited pointee false negatives and one conservative
Phi-clear false positive are characterized separately with their semantic
expectations. This is not a general heap-alias or helper-pointee model.

Helper writes, helper reads of caller-created maps, and helper-returned maps are
not summarized by this model. Unknown helper effects may cause missed flows or
leave earlier candidate writes alive. These are explicit limitations, not
claims that helper flows are clean. Dedicated characterization tests preserve
three known helper false negatives separately from supported cases. General
heap/global map aliasing, reflection, concurrent mutation, and omitted bodies
remain outside this local model. No whole-map fallback is used.

## Cost and determinism

The read builds a query-local index of relevant map events. Each candidate then
uses a finite CFG worklist with visited instruction cursors. With W candidate
writes, I instructions, and E CFG edges, candidate liveness costs
O(W × (I + E)) per read, in addition to alias/event indexing and key-type comparison costs. There is no runtime
map enumeration, runtime loop unrolling, or enumeration of execution paths.
Repeated reads repeat the query; there is no global cache retaining SSA programs.
This bound applies to this local range model, not the entire analyzer or its
other helper summaries.

Candidate order follows stable SSA block/instruction order, and duplicate values
are removed without reordering. Benchmarks keep SSA construction outside the
timed loop and exercise clean and tainted maps, loop backedges, overwrite/delete
heavy inputs, and repeated reads at increasing static input sizes.
