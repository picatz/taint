# Models (data-driven taint rules)

Models let you extend the engine's built-in knowledge — sources, sinks,
sanitizers, and flow summaries — with data instead of code. They cover the
frameworks and helpers the built-in detectors don't, and they are additive:
your models augment the built-in rules, they never replace them.

A model is written in YAML, one package per document (documents are separated
by `---`). Identifiers are the fully-qualified strings the engine matches
against — the same form the built-in rules use.

## Schema

```yaml
package: github.com/acme/db          # the import path this model describes

sinks:
  - method: "(*github.com/acme/db.Conn).Exec"   # func or method that is a sink
    args: [0]                                    # parameter positions that are the
                                                 # injection channel (see below)
    kind: sql-injection                          # optional, informational label

sources:
  - type: "*github.com/acme/http.Request"        # values of this type are tainted
  - call: "github.com/acme/http.UserInput"       # this call's return value is tainted

sanitizers:
  - func: "github.com/acme/safe.Escape"          # neutralizes taint

summaries:
  - func: "github.com/acme/util.Concat"          # taint flows from arguments...
    from: [0, 1]                                  # ...these parameters...
    to: return                                    # ...to the result (the default)
```

Every section is optional. A file may hold many packages:

```yaml
package: github.com/acme/db
sinks:
  - { method: "(*github.com/acme/db.Conn).Exec", args: [0], kind: sql-injection }
---
package: github.com/acme/log
sinks:
  - { method: "(*github.com/acme/log.Logger).Printf", kind: log-injection }
```

### Identifiers

- A package function is `import/path.Func`, e.g. `os/exec.Command`.
- A method is `(Receiver).Method`, where the receiver is fully qualified and
  keeps its pointer star: `(*database/sql.DB).Query`. Value receivers and
  interface methods omit the star: `(github.com/go-logr/logr.Logger).Info`.
- A type is its fully-qualified form, e.g. `*net/http.Request`.

You can read these off `ssadump` output or the built-in rule lists in the
detector packages if you're unsure of the exact spelling.

### Argument positions (`args` and `from`)

`args` (for sinks) and `from` (for summaries) are **logical parameter
positions as written in the source signature, excluding the receiver**, and
are zero-based. For `func (c *Conn) Exec(ctx context.Context, sql string)`,
`ctx` is `0` and `sql` is `1`. Omitting the list means *every* parameter is a
channel.

Selecting only the argument that actually carries the danger keeps bound
query parameters and other safe arguments from producing false positives.

## Using models

### From the library

```go
models, err := taint.LoadModels(os.DirFS("models"))   // a directory of YAML
if err != nil {
    log.Fatal(err)
}
diags := taint.CheckDetailed(cg, sources, sinks, taint.WithModels(models...))
```

`taint.ParseModels(io.Reader)` parses a single stream, `taint.LoadModels(fs.FS,
...glob)` loads matching files from a filesystem, and
`taint.ModelsFromPath(path)` accepts either a file or a directory. Parsing
validates every model and reports the first problem it finds.

### From the CLIs

Every detector CLI (`sqli`, `logi`, `cmdi`, `xss`, `ptrv`, `ssrf`) accepts a
`-models` flag pointing at a YAML file or a directory of them:

```console
$ sqli -models ./models ./...
```

For import-aware gating to run your model, its `package` should be an import
path the analyzed program actually imports.

## Worked example

Model a custom database helper the built-in `sqli` rules don't know about:

```yaml
# models/acme-db.yaml
package: github.com/acme/db
sinks:
  - method: "(*github.com/acme/db.Conn).Exec"
    args: [1]              # Exec(ctx, sql): only the SQL text is the channel
    kind: sql-injection
```

```console
$ sqli -models models/acme-db.yaml ./...
```

A call like `conn.Exec(ctx, r.URL.Query().Get("q"))` is now reported, while
`conn.Exec(ctx, "SELECT 1", userID)` — constant SQL with a bound parameter —
stays clean.

## Limitations

- Summaries flow only to the return value (`to: return`); field- and
  element-level access paths are not modeled yet.
- Import-aware gating in the CLIs keys on the model's `package`, so it should
  match the imported path.

These are deliberate first-phase scoping; see
[design/models-as-data.md](design/models-as-data.md) for the direction.
