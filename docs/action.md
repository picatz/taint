# GitHub Action

`action.yml` at the repository root is a composite GitHub Action that installs
one or more of the taint analyzer CLIs (`sqli`, `cmdi`, `ptrv`, `ssrf`, `xss`,
`logi`) at the action's own ref, runs each against a target Go package
pattern, and (by default) uploads the resulting SARIF to GitHub code
scanning.

## Inputs

| Input        | Default                             | Description                                                                 |
| ------------ | ------------------------------------ | ----------------------------------------------------------------------------|
| `detectors`  | `sqli,cmdi,ptrv,ssrf,xss,logi`        | Comma-separated subset of the six detector CLIs to run.                     |
| `target`     | `./...`                               | Go package pattern passed to each detector CLI.                             |
| `upload`     | `true`                                | Whether to upload each detector's SARIF to GitHub code scanning.            |

## Outputs

| Output        | Description                                                        |
| ------------- | -------------------------------------------------------------------|
| `results-dir` | Directory containing `<detector>.sarif` for each requested detector. |

## Usage

```yaml
name: Taint Analysis

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

permissions:
  contents: read

jobs:
  taint:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # required to upload SARIF to code scanning
    steps:
      - uses: actions/checkout@v4

      - uses: picatz/taint@v0
        with:
          detectors: sqli,cmdi,ptrv,ssrf,xss,logi
          target: ./...
          upload: true
```

To run only a subset of detectors (e.g. just SQL and command injection) and
skip the code scanning upload (for example, to inspect the SARIF as a build
artifact instead):

```yaml
      - uses: picatz/taint@v0
        id: taint
        with:
          detectors: sqli,cmdi
          upload: false

      - uses: actions/upload-artifact@v4
        with:
          name: taint-sarif
          path: ${{ steps.taint.outputs.results-dir }}
```

## Categories

Each detector's SARIF is uploaded with its own `category` (`taint-sqli`,
`taint-cmdi`, `taint-ptrv`, `taint-ssrf`, `taint-xss`, `taint-logi`). GitHub
code scanning treats results with different categories as independent
analyses, so running multiple detectors in the same workflow does not cause
one detector's findings to overwrite another's.

## Notes and open decisions

- This is a first-pass skeleton, versioned and released alongside the rest of
  this repository rather than split into a separate `picatz/taint-action`
  repository. Splitting into its own repo (with its own semver and
  marketplace listing) is a reasonable follow-up once the action has some
  mileage, but isn't done here.
- Publishing to the GitHub Marketplace is deferred; the action works today
  as `uses: picatz/taint@<ref>` from any workflow without a marketplace
  listing.
- The composite action supports exactly the six known detector names because
  composite actions cannot loop `uses:` steps over a runtime-determined list;
  see the comments in `action.yml` for the mechanics.
