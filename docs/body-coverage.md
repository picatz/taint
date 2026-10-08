# Whole-program body coverage

`taint scan` connects selected packages through one call graph. It does not
build source bodies for every transitive dependency. By default,
`-bodies=selected` builds bodies only for initial packages matched by the
supplied patterns. Imported
packages still have SSA declarations and may have modeled behavior. An
unmodeled helper whose body is omitted can interrupt a taint path.

Use `taint scan -coverage ./controllers ./object` to print a package-coverage
explanation to stderr. It lists imported, unselected dependencies belonging to
any selected package's exact module. Finding output (text, JSON, or SARIF),
exit status, roots, models, and source/sink matching are unchanged. The flag
adds no package loads or SSA builds. It traverses already loaded metadata and
sorts package IDs, using memory proportional to the number of dependencies.

Module identity includes module path, version, directory, go.mod file, and
replacement identity. A workspace's unselected sibling module is not treated
as the same module merely because both modules have `Main` set. Selecting
packages from multiple modules includes each of those module identities.
Package IDs preserve test variants. Missing module path or both directory and
go.mod metadata are treated conservatively as unknown; the diagnostic reports
when selected inputs cannot be classified. Other dependencies are counted,
not individually printed; these include third-party packages, standard-library
packages, and dependencies with unknown module identity.

This is a coverage diagnostic, not a completeness or recall guarantee.
Assembly/external declarations and synthetic functions may lack bodies even
in a selected package. A zero omitted-same-module count does not establish that
all dependencies have bodies or that all vulnerabilities can be found.

Explicitly selecting an additional package can expose its helper bodies, but
also changes the analysis input and potentially its library roots and matches.
Do not treat a result from wider patterns as an engine improvement on an
unchanged benchmark. The opt-in mode below expands body inputs without widening
roots or source/sink ownership.

## Bounded same-module bodies

`taint scan -scope=selected -bodies=same-module` builds bodies for eligible
unselected dependencies already reachable through the loaded import graph.
Both additional-input budgets must be supplied and strictly positive:

```sh
taint scan -scope=selected -bodies=same-module \
  -max-body-packages=10 -max-body-syntax-bytes=1048576 \
  -coverage ./caller
```

These example limits allow at most 10 additional package identities and 1 MiB
of additional parsed syntax. They are not recommended defaults. Zero is not
unlimited. `-bodies=selected` is the unchanged default and requires zero limits;
nonzero limits there are rejected rather than silently ignored. Same-module
mode requires `-scope=selected`; it is unavailable with legacy scope.

The loader uses a single package load. It admits only imports matching an
original selected package's known exact module identity, including its full
replacement chain. It does not search module directories or reload packages.
Unselected workspace siblings and nested modules remain external unless their
own exact module is represented among the original selected inputs. A shared
replacement directory or equal path alone does not establish module identity.
Standard-library and unknown-identity dependencies remain excluded. Unknown or
incomplete selected module identity is an error in this mode.

The package limit counts additional distinct package identities, including each
test variant separately. The syntax limit sums the loaded token-file sizes for
every syntax entry of each additional package. Shared files are charged again
for distinct test variants; no filesystem reread is used. This measures parsed
input bytes, not AST heap or SSA allocations. Selected packages are outside
these additional-input budgets.

The entire eligible set is validated before SSA construction. Exceeding either
budget, arithmetic overflow, or missing/inconsistent required type or syntax
metadata fails the whole load. Budget failures report required and allowed
totals. There is no truncated subset, fallback, or partial findings: exit status
is 1, diagnostics go to stderr, and stdout is empty for every finding format.

Roots and source/sink occurrence ownership remain exactly the original selected
inputs. Imported exported functions do not become independent roots. Added
bodies permit existing propagation and sanitizer handling; imported initializers
may be reached through selected initializer edges. SSA construction still builds
all admitted package bodies, including unreachable declarations. External or
assembly declarations can legitimately lack bodies.

With `-coverage`, stderr reports the effective mode, selected and built package
IDs, omitted eligible count, used/configured budgets, parsed bytes, and excluded
dependency count. Coverage on/off preserves stdout and exit status for the same
mode in text, JSON, and SARIF. Opting into added bodies can itself change findings.
The original selected-body diagnostics remain unchanged.

Budgets are input-complexity guards, not hard RSS, runtime, or whole-program SSA
size guarantees. Context cancellation is checked around loading, accounting,
and SSA work, but cannot promptly interrupt SSA construction or `Program.Build`.
Use an external process timeout when hard termination is required and treat a
terminated measurement as incomplete. This option applies only to `taint scan`;
per-package analyzers, interactive mode, vulncheck, and existing evaluation
manifests are unchanged. Record opt-in evaluations separately from default
precision baselines.
