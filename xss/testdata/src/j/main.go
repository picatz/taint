// Channel/goroutine handoff regression.
//
// `dest` arrives through a channel — its origin is opaque to the
// destination-provenance walker. The walker MUST return provUnknown for
// channel receives, which preserves the diagnostic. If a future refactor
// silently classified channel results as non-ResponseWriter, this test
// would catch the regression.
package main

import (
	"io"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	ch := make(chan io.Writer, 1)
	ch <- w
	dest := <-ch
	dest.Write([]byte(r.URL.Query().Get("x"))) // want "potential XSS"
}

func main() {
	http.HandleFunc("/", handler)
	_ = http.ListenAndServe(":8080", nil)
}
