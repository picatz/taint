# Vulnerability scanning (`vuln`)

`vuln` scans Go code for known vulnerabilities from the
[Go vulnerability database](https://vuln.go.dev) and ranks each finding by how
strongly your code is exposed. It is this project's answer to `govulncheck`:
the same authoritative data and call-graph reachability, plus a **taint tier**
that reports whether attacker-controlled data actually reaches the vulnerable
code, with an evidence trace.

## Exposure tiers

Every finding is reported at the highest tier established for it. Higher tiers
are strictly more specific: each implies every lower tier holds.

| Tier | Meaning |
| --- | --- |
| `taint` | Attacker-controlled data reaches the vulnerable symbol. The strongest signal, unique to a taint-aware scanner, with a data-flow trace. |
| `symbol` | A vulnerable symbol is reachable through the call graph. This is `govulncheck`'s headline precision. |
| `package` | Your build imports a vulnerable package, but no vulnerable symbol was reached. |
| `module` | Your build depends on a vulnerable module version. The only tier available for advisories with no symbol data (about 79% of the database). |

The tiers degrade loudly, never silently: an advisory with no symbol data still
surfaces at module tier, and a reachable-but-untainted symbol is reported as
`symbol` rather than dropped. A `taint` finding tells you to act now; a `module`
finding tells you to update when you can.

## Command line

```
vuln [flags] [packages]
```

```console
$ vuln ./...
Found 3 vulnerability finding(s): 1 taint, 1 package, 1 module.

GO-2021-0113 [TAINT] Out-of-bounds read in golang.org/x/text/language
  module:  golang.org/x/text @ v0.3.0
  fix:     upgrade to 0.3.7
  more:    https://pkg.go.dev/vuln/GO-2021-0113
  attacker-controlled data reaches the vulnerable symbol
  symbol:  golang.org/x/text/language.Parse
  data flow:
    main.go:12:30: value matched configured source
    main.go:12:45: no configured sanitizer matched sink argument
    main.go:12:27: callsite matched configured sink
  call stack:
    example.com/app.main
      net/http.HandleFunc  (main.go:11:17)
        example.com/app.main$1  (main.go:11:17)
          golang.org/x/text/language.Parse  (main.go:12:27)
...
```

### Flags

| Flag | Description |
| --- | --- |
| `-C dir` | Change to `dir` before scanning. |
| `-format fmt` | `text` (default), `json`, or `sarif`. |
| `-db path/url` | Database location: the live endpoint (default `https://vuln.go.dev`) or a local directory (an unpacked `vulndb.zip` or a custom mirror). |
| `-min tier` | Report only findings at or above `tier` (`module`, `package`, `symbol`, `taint`). |
| `-tags tags` | Comma-separated build tags. |
| `-test` | Include test files and packages. |
| `-go version` | Go toolchain version for standard-library matching (default: the running toolchain). |
| `-no-cache` | Do not cache downloaded advisories on disk. |

### Exit status

Following `govulncheck`'s convention so CI can gate on it:

- `0`: no findings.
- `3`: findings reported.
- `1`: error.

## CI/CD

Fail a build only when a vulnerable symbol is actually reachable, while still
recording lower-tier findings out of band:

```yaml
- name: Vulnerability scan (gate on reachable symbols)
  run: go run github.com/picatz/taint/cmd/vuln -min symbol ./...

- name: Full SARIF report for code scanning
  if: always()
  run: go run github.com/picatz/taint/cmd/vuln -format sarif ./... > vuln.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: vuln.sarif
```

Gating on `-min taint` is stricter still: the build fails only when untrusted
input can reach the vulnerability. Because the SARIF rule id is the advisory id
(`GO-YYYY-NNNN`), findings deduplicate and link back to the advisory in the
code-scanning UI.

## Offline and air-gapped use

Point `-db` at a local copy of the database:

```console
$ curl -sSL https://vuln.go.dev/vulndb.zip -o vulndb.zip
$ unzip -q vulndb.zip -d vulndb
$ vuln -db ./vulndb ./...
```

Online runs cache advisories under `os.UserCacheDir()/taint/vulndb`, so repeated
scans (a CI job, an editor loop) reuse prior downloads.

## Interactive shell

The `taint` interactive tool has a `vuln` command:

```
taint> vuln ./service --min symbol
```

It loads and analyzes the target fresh, so it works before any `load`.

## What the taint tier considers "attacker-controlled"

By default the taint tier treats an inbound `*net/http.Request` and a decoded
protocol-buffer message as sources, matching the built-in detectors. When using
the library directly, supply a different threat model with `WithSources`, or
extend the flow rules with `WithModels` (the same
[models-as-data](models.md) format the detectors use). A vulnerability whose
exploit path is not HTTP (a CLI argument, an environment variable, a
message-queue payload) will show at `symbol` tier until its source is modeled.

## Library

```go
import (
	"github.com/picatz/taint/vulncheck"
	"github.com/picatz/taint/vulndb"
)

src, _ := vulndb.NewHTTPSource(vulndb.DefaultBaseURL, nil)
target, _ := vulncheck.Load(ctx, vulncheck.LoadConfig{Dir: "."})
res, _ := vulncheck.Scan(ctx, target, src)
for _, f := range res.Findings {
	fmt.Println(f.OSV, f.Tier, f.Module, f.Symbol)
}
```

`vulndb` is a standalone, dependency-light reader for the Go vulnerability
database (OSV types, version matching, an index-then-fetch client, HTTP and
`fs.FS` sources, and a caching layer). `vulncheck` is the scanner built on the
taint engine.

## Relationship to govulncheck

`vuln` reads the same database and uses the same call-graph precision for the
symbol tier. It differs in one respect that matters: `govulncheck` proves a
static call path *exists*; `vuln` additionally asks whether *attacker-controlled
data flows along it*. That extra tier is a prioritization signal, not a
correctness claim in either direction. A `symbol` finding with no taint path is
still a real reachable vulnerability, and taint analysis can miss flows, so a
reported tier is a floor on exposure, never a ceiling on risk.
