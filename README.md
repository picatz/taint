# taint

Implements static [taint analysis](https://en.wikipedia.org/wiki/Taint_checking) for Go programs. 

Taint analysis is a technique for identifying the flow of sensitive data through a program. 
It can be used to identify potential security vulnerabilities, such as SQL injection or 
cross-site scripting (XSS) attacks, by understanding how this data is used and transformed 
as it flows through the code.

A "**source**" is a point in the program where sensitive data originates, typically from user 
input, such as data entered into a form on a web page, or data loaded from an external source. 
A "**sink**" is a point in the program where sensitive data is used or transmitted to exploit 
the program.

## Example

This code generates a function call graph rooted at a program's `main` function and 
then runs taint analysis on it. If the program uses `database/sql`, the taint analysis
will determine if the program is vulnerable to SQL injection such that any of the given
sources reach the given sinks.

```go
cg, _ := callgraph.New(mainFn, buildSSA.SrcFuncs...)

sources := taint.NewSources(
	"*net/http.Request",
)

sinks := taint.NewSources(
	"(*database/sql.DB).Query",
	"(*database/sql.DB).QueryContext",
	"(*database/sql.DB).QueryRow",
	"(*database/sql.DB).QueryRowContext",
	"(*database/sql.Tx).Query",
	"(*database/sql.Tx).QueryContext",
	"(*database/sql.Tx).QueryRow",
	"(*database/sql.Tx).QueryRowContext",
)

results, _ := taint.Check(cg, sources, sinks)

for _, result := range results {
	// We found a query edge that is tainted by user input, is it
	// doing this safely? We expect this to be safely done by
	// providing a prepared statement as a constant in the query
	// (first argument after context).
	queryEdge := result.Path[len(result.Path)-1]

	// Get the query arguments, skipping the first element, pointer to the DB.
	queryArgs := queryEdge.Site.Common().Args[1:]

	// Skip the context argument, if using a *Context query variant.
	if strings.HasPrefix(queryEdge.Site.Value().Call.Value.String(), "Context") {
		queryArgs = queryArgs[1:]
	}
}
```

### `sqli`

The `sqli` analyzer is a CLI tool that demonstrates usage of the `taint` package to find
potential SQL injections.

```console
$ go install github.com/picatz/taint/cmd/sqli@latest
```

```console
$ cd sql/injection/testdata/src/example
$ cat main.go
package main

import (
        "database/sql"
        "net/http"
)

func business(db *sql.DB, q string) {
        db.Query(q) // potential sql injection
}

func run() {
        db, _ := sql.Open("sqlite3", ":memory:")

        mux := http.NewServeMux()

        mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
                business(db, r.URL.Query().Get("sql-query"))
        })

        http.ListenAndServe(":8080", mux)
}

func main() {
        run()
}
$ sqli main.go
./sql/injection/testdata/src/example/main.go:9:10: potential sql injection
```

### `logi`

The `logi` analyzer is a CLI tool that demonstrates usage of the `taint` package to find
potential log injections.

```console
$ go install github.com/picatz/taint/cmd/logi@latest
```

```console
$ cd log/injection/testdata/src/a
$ cat main.go
package main

import (
        "log"
        "net/http"
)

func main() {
        http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
                log.Println(r.URL.Query().Get("input"))
        })

        http.ListenAndServe(":8080", nil)
}
$ logi main.go
./log/injection/testdata/src/example/main.go:10:14: potential log injection
```

### `xss`

The `xss` analyzer is a CLI tool that demonstrates usage of the `taint` package to find
potential cross-site scripting (XSS) vulnerabilities.

```console
$ go install github.com/picatz/taint/cmd/xss@latest
```

```console
$ cd xss/testdata/src/a
$ cat main.go
package main

import (
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.URL.Query().Get("input"))) // want "potential XSS"
	})

	http.ListenAndServe(":8080", nil)
}
$ xss main.go
./xss/testdata/src/example/main.go:9:8: potential XSS
```
