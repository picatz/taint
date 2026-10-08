# Selected-package analysis profile

`taint scan -scope=selected [packages]` opts into a bounded profile with three
separate controls:

- **Roots:** exactly the selected packages' executable `main` and package `init`
  functions when at least one executable main is selected. Otherwise, selected
  package initializers, exported functions, and exported methods in the value
  and pointer method sets of exported types are roots. Roots are deduplicated
  by SSA identity. A synthetic graph root connects every retained entry.
- **Occurrences:** source and sink occurrences must belong to an original
  selected package, using the exact type-package identities from the same load.
  The package declaring a modeled symbol is not the filter: calls to external
  `net/http`, `database/sql`, framework, and other modeled APIs inside selected
  code remain eligible. Selecting packages does not make all their values tainted.
- **Bodies:** only original selected packages are inputs to SSA source-body
  construction by default (`-bodies=selected`). Opt-in `-bodies=same-module`
  adds eligible imported bodies under explicit package and parsed-byte budgets,
  without expanding roots or source/sink ownership. See [body coverage](body-coverage.md).

The default is `-scope=legacy`, also used when the flag is absent. Default roots,
matching, output formats, exit codes, and precision baselines are unchanged.
Selected results can differ: in particular package initializers are explicit
roots even for a single selected command. This is not a completeness guarantee.
The call graph may contain nodes outside the reachable selected roots.

## Initializers, methods, and synthetic functions

A mixed selection of commands and libraries uses the commands' `main`/`init`
roots. Library exports are not independently rooted in that case; a selected
library initializer can still be reached through a command initializer.
For a library-only selection, each selected package's initializer is a root.
Source-written `init` functions are reached through that package initializer.

Both pointer and value exported API method sets are included. Promoted methods
exposed through a selected exported type remain roots, but exposure does not
rewrite where the method was declared. Imported declaration-only methods do not
acquire bodies or new source ownership. Synthetic receiver adapters are resolved
by the existing occurrence matcher using their active caller path; an unknown
or ambiguous synthetic owner is conservatively excluded. Merely promoting an
unselected method is not a guarantee of source eligibility or body coverage.

Closures and instantiated generic bodies use the existing package/origin
ownership rules. Propagation and sanitizers are not restricted by occurrence
scope: existing taint may pass through a helper with an available body without
allowing that helper to introduce an out-of-scope source or sink. With this
default selected-body-only mode, an ordinary unselected imported helper has no
source body to inspect. The bounded same-module mode can provide that body. Opaque calls retain existing model and summary behavior; no
blanket propagation or taint rule is added.

## Diagnostics and APIs

`-coverage` continues to explain body inputs and omitted dependencies on stderr.
For selected scope it also reports the effective roots/occurrences/bodies profile.
Text, JSON, and SARIF findings on stdout are unchanged by this explanation.
Unknown scope values fail before loading packages.

The shared internal loader accepts `Config.Scope`; empty and `ScopeLegacy`
preserve legacy behavior. `Program.Packages` remains the original loaded package
list. `Program.MatchPackages` provides matching identities in `ScopeSelected`;
callers must pass these to `taint.WithMatchPackages` when checking its graph.
Root selection alone does not enforce occurrence eligibility.

Each detector adds `CheckWithOptions(ctx, graph, ...taint.Option)` alongside the
unchanged `Check(ctx, graph)`. Built-in and configured models, sink-argument
selectors, sanitizers, SQL constant-query suppression, and XSS destination
filtering remain in force. Caller options add customization; the explicit
context takes precedence over an options-supplied context.

This flag applies only to `taint scan`. Per-package analyzers, interactive mode,
advisory/vulncheck, and existing evaluation manifests keep their legacy profile.
Selected-profile evaluations must be recorded separately from default precision
snapshots. Bounded same-module dependency bodies require this selected profile
and both explicit positive additional-input budgets.

With `-test`, original and test-augmented packages can share import paths while
having distinct type identities; each original loaded identity is retained.
Generated test mains follow the same main-precedence rule. The existing call
resolver may not connect a test callback from that generated main, so selecting
tests does not guarantee callback coverage in either profile.
