# Roadmap

Where the engine is going, phased so that measurement lands before engine
surgery. Grounded in a July 2026 review of the engine internals and the
surrounding ecosystem (govulncheck's callgraph pipeline, CodeQL's Go models,
go-flow-levee's archiving, Argot's function summaries, gosec's taint engine).

## P0 — Stabilize (done)

- Land the parameter/receiver precision work with the invoke-resolution
  panic fixed and pinned by a regression test.
- Repo hygiene: stale profiling artifacts removed.

## P1 — Measurement (in progress)

- Recall harness: ground-truth expected findings for eval targets, pinned
  real-CVE targets (Gogs, Casdoor, pREST, eKuiper, go-dvwa), and a
  per-detector precision/recall scoreboard. Published single-tool recall on
  real CVEs runs 11–27%, so 20–40% CVE recall is the competitive bar.
- Engine benchmarks: linear, diamond (path explosion), many-sink, and
  many-finding shapes, with a baseline table in docs/performance.md.

## P2 — Substrate (in progress)

- x/tools v0.34.0 → v0.47.0, alias-type (`types.Unalias`) audit.
- Dead-code removal and mechanical modernization of the engine core.
- CI: vet, gofmt, race, govulncheck, staticcheck (done).
- Next: adopt govulncheck's callgraph recipe as the default — CHA seed →
  forward slice from entry points → VTA (twice), SSA built with
  `ssa.InstantiateGenerics`. VTA natively tracks function values through
  struct fields, globals, maps, and phis, which may subsume much of the
  custom builder. Keep both, benchmarked head-to-head on the scoreboard.

## P3 — Scalable checking

Replace exponential all-simple-paths enumeration with per-callsite analysis
and memoized function summaries. Design: docs/design/scalable-checking.md.
Every change gated by the P1 scoreboard and benchmarks.

## P4 — Models as data

Move source/sink/propagator/sanitizer knowledge from hardcoded Go tables to
embedded YAML model packs with CodeQL-style access paths, loaded per
imported package. Design: docs/design/models-as-data.md. This closes the
structural need behind issues #3 and #7.

## P5 — Distribution and v1.0

- GitHub Action (done: action.yml), GoReleaser + release workflow (done),
  first tagged release (pending).
- v1.0 API pass: distinct `Sources`/`Sinks` types (currently interchangeable
  aliases), options on `Check`, `Result.SinkType` semantics, a smaller
  `callgraphutil` surface, `log/slog` throughout.

## P6 — Differentiators

- Backtrace mode ("what reaches this sink?").
- Channel/goroutine-aware taint — a genuinely Go-specific gap no active
  tool covers.
- Branch-sensitive sanitizers (SSI/sigma-node inspired).
- Function-summary Facts serialization, the bridge to per-package
  go/analysis drivers (the only realistic golangci-lint path).
- MCP server exposing the engine to LLM-driven triage and spec inference.
