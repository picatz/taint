# Selected map-key identity

Map lookups, local writes/deletes, and the existing selected-key helper summaries
compare a known scalar key by both its runtime value and its concrete type.
In `map[any]string`, `int(1)`, `int64(1)`, and a defined integer type are different
entries. Type aliases retain their usual Go identity. The same comparison is
used for writes and kills, so a different-type clean update cannot hide an older
source, and a different-type source is not attributed to the selected entry.

## Resolution boundary

The selected-key resolver follows constants, interface boxing/interface changes,
representation-preserving type changes, supported scalar conversions, and known
successful assertions/unboxing. Existing Phi and reaching-load resolution is
retained, but every alternative must agree on both value and concrete type.
Failed or unresolved assertions remain unknown, including the zero value of a
failed comma-ok assertion.

Helper key resolution follows the existing parameter bindings beneath these
wrappers. Nested helpers retain the enclosing key-binding chain; they do not
rewrite or manufacture SSA instructions. Value-summary substitution, selected
map parameters, alias policy, depth limits, and nested event projection are
unchanged.

Fixed-width integer conversions use Go's truncation/sign-extension semantics.
Finite float and complex components are rounded to their destination widths.
This also validates destination-typed SSA constants, whose abstract values can
be retained before truncation. Fractional or out-of-range floating-to-integer
conversions, integer-to-string conversions, non-finite values, and unsupported
key expressions remain may-matches and cannot prove a kill. Native `int`, `uint`
and `uintptr` values outside the range common to 32- and 64-bit targets remain
unknown because SSA does not supply the target's type sizes here.

No general equality proof is added for identical dynamic SSA values. In
particular, NaNs are non-reflexive, including when contained in interface, array,
or struct keys. Unknown keys preserve incoming candidates conservatively.

## Separate models and remaining limits

The local map-range model and its deliberately narrower constant classifier are
unchanged, including its existing reflexive dynamic-key rules for supported
array/struct keys. Sharing the selected-key resolver with that model would expand
its traversal and work bounds, so range discovery does not call this resolver.
No helper map-range support is added.

This correction does not compose nested control-flow summaries, change recovery
handling, strengthen clean helper overwrites, or fix uncertain-map alias kills.
The inherited nested conditional clear/delete and write-then-delete limitations
remain independently characterized in `helper_summary_test.go`.

## Verification

`TestSelectedMapKeyIdentity` checks direct and helper positive/clean controls,
dynamic interface type distinctions, defined types versus aliases, wrapped
parameter substitutions, known assertions, Phi/load joins, numeric conversions,
and conservative non-scalar/NaN boundaries. Every case repeats the complete
analysis and verifies attribution/evidence order for reported flows. Existing
map-range and finite helper-reducer tests are unchanged.

```sh
go test -run '^Test(SelectedMapKey|MapKey|HelperMap|CheckDetailedMapRange|MapRange|CheckDetailedHelperMap)' -count=1 .
```
