# Source and sink occurrence scope

`CheckDetailed` accepts `WithMatchPackages(packages ...*types.Package)` to limit
where new sources and sink calls may be recognized. Pass the actual package
identities from the same loaded SSA program, for example `ssaPkg.Pkg`. Matching
is not based on an import-path prefix or a filename. A separately constructed
`types.Package` with the same path is a different identity.

Without the option, behavior remains unrestricted. `WithMatchPackages()` is an
explicit empty scope: no sources or sinks match. Nil package entries are ignored,
the argument slice is copied, and the last scope option replaces earlier ones.

Scope belongs to the occurrence, not the declaration of a modeled API. A selected
handler calling `database/sql` can match a SQL sink even though `database/sql` is
outside the scope. A source call, field access or type-source occurrence only
inside an unselected helper is not a new source. A sink call inside that helper
is excluded too. Analysis still traverses the helper: selected-source data can
flow through its arguments, return values, fields, arrays and modeled summaries.
Sanitizers remain effective inside and outside the matching scope.

Parameters with an actual caller argument follow that binding. Unbound entry
parameters can match source-type rules in their owning package. Scoped
operand/derived-value walks likewise substitute actual arguments before treating
a helper parameter as a fresh source. Type models retain their existing broad
meaning: a typed value or field access in a selected package may itself match,
regardless of where the type was declared. Scope is not a new precision mode.

Closures use their lexical package; generic instances use their origin. Package
initializers have their recorded package owner. Go SSA method-value wrappers,
method-expression thunks and promoted-method wrappers use the actual incoming
call on the active witness or return-summary path. Their modeled declaration's
package does not determine ownership. An adapter without such a call, other
unknown synthetic functions, and values with no provable occurrence owner cannot
introduce scoped sources or sinks. These conservative exclusions can reduce
coverage; they are not proof that a program is safe.

This option changes neither package loading nor function bodies, roots, graph
construction or scanner defaults. There is no CLI scope flag or automatic
same-module dependency expansion. Existing analysis limitations remain: for
example, some by-value struct-return paths conservatively propagate taint to a
clean sibling field. The paired legacy/scoped tests retain that limitation
explicitly rather than reclassifying it as a scope improvement.
