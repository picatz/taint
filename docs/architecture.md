# Architecture

`taint` is a library-first static taint engine for Go SSA programs. The current
stabilized detector families are SQL injection, log injection, and XSS.

## Callgraph Construction

Analyzer packages build SSA with `buildssa.Analyzer`, then call
`callgraphutil.NewGraph` for command packages or
`callgraphutil.CreateMultiRootCallGraph` for library packages. The callgraph
builder adds direct calls, closures, concrete interface dispatch when it can
recover receiver types, function-field calls, and a synthetic root for
multi-entry library analysis.

Analyzer CLIs expose `-callgraph=taint` by default and `-callgraph=vta` as an
alternate CHA+VTA strategy adapted from govulncheck. The selection is routed
through `callgraphutil.BuildCallGraph`, so command packages and library
packages get the same root handling across algorithms.

Edges are deduplicated at the end of construction and inbound edge lists are
rebuilt so `Node.In` and `Node.Out` stay consistent. Path search uses simple
path traversal to avoid cycles while preserving distinct paths to the same
target.

## Taint Search

`Check` is the compatibility API and delegates to `CheckDetailed`. The detailed
engine finds concrete call edges that match sink rules, selects sink arguments,
and asks whether any selected value derives from a configured source. Results
are deduplicated by sink callsite and source type, preferring richer paths so
wrapper calls retain useful evidence.

The recursive SSA walk follows common value forms: parameters, calls, returns,
allocations, stores, fields, indexes, slices, phi nodes, conversions, interface
changes, closures, map updates, and binary/unary expressions. Pointer loads use
basic flow-sensitive reachability, so stores that cannot reach the load do not
taint it or satisfy sanitizer coverage. Return-summary modeling maps callee
return values back to caller arguments and has a fixed recursion bound to avoid
unbounded summaries.

## Rule Registries

Sources, sinks, sanitizers, and propagators are represented as typed internal
rules. Public `Sources` and `Sinks` remain string sets for compatibility, while
the engine turns them into exact function, method, and type matchers.

Default propagation rules model known transforms such as `fmt.Sprintf`,
`append`, `strings.Join`, common `strings`/`bytes` transforms, `io.ReadAll`,
`bufio.NewReader`, `bufio.NewReaderSize`, `zap.String`, and
`html.EscapeString` when that call is not configured as a sanitizer. The engine
also models `strings.Builder` and `bytes.Buffer` writes that can reach later
`String` or `Bytes` reads.

Sanitizers are value-specific. A sanitizer suppresses a finding only when the
actual value passed to the sink is the sanitizer result, possibly wrapped by SSA
conversions or interface changes. A sanitizer nested inside a larger expression
is recorded as rejected unless the whole sink value is covered.

## Diagnostics

`CheckDetailed` returns `Diagnostics`. Each `Diagnostic` contains the legacy
`Result` plus ordered evidence entries for source matches, propagation,
parameter mapping, sanitizer decisions, sink matches, and unresolved or
synthetic modeling. Analyzers can report the concrete unsafe callsite and use
the evidence for debug or future CLI output.

## Conservative Limits

The engine is intentionally conservative where SSA or callgraph information is
incomplete. Dynamic reflection, complex aliasing, data-dependent dispatch, and
some indirect function-field flows may be unresolved. Callback arguments are
linked at observed dispatch sites, plus a small set of known registration APIs
such as `net/http.HandleFunc`; callbacks that are only passed to a function are
not treated as reachable unless the callee invokes or registers them. Unknown or
synthetic modeling is captured in diagnostic evidence instead of hidden from
callers.
