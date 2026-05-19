// Regression for the chi false positive at middleware/terminal.go:57.
//
// `cW` is a helper that writes its `color` argument (a package-level
// constant) into an io.Writer destination. In chi, that destination is the
// internal `*bytes.Buffer` of a log entry — never an HTTP response. The
// destination-provenance filter must classify the buffer write as
// provNotResponseWriter and drop the diagnostic.
//
// On the same handler, the direct `w.Write([]byte(tainted))` flow MUST
// still fire — the destination there flows from `http.ResponseWriter`.
package main

import (
	"bytes"
	"io"
	"net/http"
)

var ansi = []byte("\x1b[31m")

// cW writes a constant color into whatever io.Writer is passed.
func cW(w io.Writer, color []byte, s string) {
	w.Write(color)       // safe: dest is *bytes.Buffer in our caller
	io.WriteString(w, s) // safe: same
}

func logEntry(r *http.Request) {
	var buf bytes.Buffer
	cW(&buf, ansi, r.URL.Path)
	_ = buf
}

func handler(w http.ResponseWriter, r *http.Request) {
	logEntry(r)
	w.Write([]byte(r.URL.Query().Get("x"))) // want "potential XSS"
}

func main() {
	http.HandleFunc("/", handler)
	_ = http.ListenAndServe(":8080", nil)
}
