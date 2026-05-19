// Regression that locks in detection when the destination is an io.Writer
// interface value that wraps the underlying http.ResponseWriter via a
// factory call (here bufio.NewWriter). The destination-provenance walker
// hits *ssa.Call returning *bufio.Writer and returns provUnknown — the
// finding must be preserved on unknown.
//
// The Write happens via the io.Writer interface (dest.Write) so the
// existing (io.Writer).Write sink rule matches.
package main

import (
	"bufio"
	"io"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	var dest io.Writer = bufio.NewWriter(w)
	dest.Write([]byte(r.URL.Query().Get("x"))) // want "potential XSS"
}

func main() {
	http.HandleFunc("/", handler)
	_ = http.ListenAndServe(":8080", nil)
}
