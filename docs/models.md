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
  - type: "*github.com/acme/http.Request"        # field-sensitive: only req.Body
    field: Body                                  # is tainted, not req.Method

sanitizers:
  - func: "github.com/acme/safe.Escape"          # neutralizes taint

summaries:
  - func: "github.com/acme/util.Concat"          # taint flows from arguments...
    from: [0, 1]                                  # ...these parameters (or "receiver")...
    to: result                                    # ...to the result (the default)
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

### Field-sensitive sources

A source with a `field` taints only accesses to that struct field, not the
whole value or its siblings:

```yaml
sources:
  - type: "*github.com/acme/api.Request"
    field: Body
```

With this model, `req.Body` reaching a sink is reported, but `req.Method` — a
different field of the same request — stays clean, and passing `req` itself to
a sink does not flag. `field` requires `type`.

### Argument selectors (`args` and `from`)

`args` (for sinks) and `from` (for summaries) are lists of **argument
selectors**. Each selector names one or more parameters — **zero-based, as
written in the source signature, excluding the receiver**. For
`func (c *Conn) Exec(ctx context.Context, sql string)`, `ctx` is `0` and `sql`
is `1`. Omitting the list means *every* parameter is selected.

Selecting only the argument that actually carries the danger keeps bound query
parameters and other safe arguments from producing false positives.

A selector is written in any of these forms:

| Selector | Selects |
| --- | --- |
| `0` | argument 0 |
| `0..2` | arguments 0, 1, and 2 (inclusive) |
| `receiver` | the receiver of a method call |
| `Argument[1]` | argument 1 (CodeQL-compatible spelling) |
| `Argument[0..2]` | a CodeQL-compatible range |
| `Argument[receiver]` | the receiver |

```yaml
sinks:
  - method: "(*acme.Cmd).Run"
    args: [receiver]          # the tainted command is the receiver itself
  - method: "acme.Printf"
    args: ["0..3"]            # any of the first four arguments

summaries:
  - func: "(*acme.Builder).String"
    from: [receiver]          # taint on the builder flows to its result
    to: result
```

A sink selector may carry a trailing **field access**, e.g.
`Argument[0].Field[Message]` or the shorthand `0.Field[Message]` (a CodeQL
`pkg.T.` qualifier on the field name is accepted and stripped). This is
field-sensitive: the sink fires only when that struct field of the argument is
the tainted channel, not the whole value or a sibling field — see below. An
**element access** (`Argument[0].ArrayElement`) is still interpreted loosely and
resolves to the whole argument, as does a field access used in a summary `from`
selector (summaries are not field-sensitive yet).

When a sink lists no `args` and no `select`, it inherits the engine's built-in
selector for that method — so naming a well-known standard-library sink yields
its precise channel — falling back to every argument for methods the engine
does not specifically model.

### Named selectors (`select`)

Some channels can't be expressed positionally — for example, "only the URL
argument, accounting for a bound method value." A sink may instead name a
built-in selector with `select` (mutually exclusive with `args`):

```yaml
sinks:
  - method: "(*net/http.Client).Post"
    select: http-post-url      # only the URL, not the body or content type
```

The available names are `exec-command` (the command string, including the
argument to `sh -c`), `http-post-url`, `sql-query` (the SQL text after a
context argument), and `sql-prepare` (the SQL text of a `Prepare(ctx, name,
sql)` method).

### Field-sensitive sinks

When the dangerous channel is one field of a struct argument — not the whole
value — give the selector a field access:

```yaml
sinks:
  - method: "github.com/acme/log.Write"
    args: ["0.Field[Message]"]   # only entry.Message is the channel
```

With this model, `Write(Entry{Message: userInput})` is reported, but
`Write(Entry{Other: userInput})` — a sibling field — stays clean, and a struct
whose `Message` is a constant does not flag even if another field is tainted.

This resolves precisely for the common shapes: a struct built and passed by
value or pointer, a struct returned from an analyzable helper, and a struct
threaded through parameters. When the field cannot be resolved to a specific
store — for example a struct copied wholesale out of opaque third-party code, or
a field written only inside a helper through a passed pointer — the check falls
back to the whole value, so it never reports *less* than the same sink without a
field would. The field name is matched against the struct's declared fields.

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

Because `LoadModels` takes an `fs.FS`, you can ship a pack of models embedded
in your own program and load it with no files on disk:

```go
//go:embed models
var modelsFS embed.FS

sub, _ := fs.Sub(modelsFS, "models")
models, err := taint.LoadModels(sub)
```

A ready-to-copy example pack that exercises every rule kind and an access-path
selector lives at [`testdata/models/example.yaml`](../testdata/models/example.yaml).

### From the CLIs

Every detector CLI (`sqli`, `logi`, `cmdi`, `xss`, `ptrv`, `ssrf`) accepts a
`-models` flag pointing at a YAML file or a directory of them:

```console
$ sqli -models ./models ./...
```

For import-aware gating to run your model, its `package` should be an import
path the analyzed program actually imports.

### From the interactive tool

The `taint` interactive tool has a `models` command for iterating on a model
and debugging it. `models <path>` loads a file or directory and prints what
each model contributes — sources, sinks (with their argument selectors),
sanitizers, and summaries — so you can confirm it parsed as intended:

```console
taint> models ./models/acme-db.yaml
✓ loaded 1 model(s)
package github.com/acme/db
  sink   (*github.com/acme/db.Conn).Exec args=[1] kind=sql-injection
```

Loaded models are then applied by the `check` command, so you can load a
model and immediately test a source→sink flow against it.

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

- Summaries flow only to the result (`to: result`); flowing taint into an
  output-parameter is not modeled yet.
- Sources (via `field`) and sinks (via an `args` field access) are
  field-sensitive; **summaries** are not — a field access in a `from` selector
  resolves to the whole argument. Element-level access paths
  (`Argument[0].ArrayElement`) are also whole-value everywhere.
- A field-sensitive sink resolves a field written only inside a helper (through
  a passed pointer) conservatively as the whole value; a precise cross-procedure
  field store is future work.
- Import-aware gating in the CLIs keys on the model's `package`, so it should
  match the imported path.

These are deliberate first-phase scoping; see
[design/models-as-data.md](design/models-as-data.md) for the direction.
