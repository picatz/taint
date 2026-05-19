// Regression based on the gorilla-mux finding at mux_test.go:2985.
//
// The first log call below logs the error returned by (*http.Request).Write —
// a stdlib method whose SSA body is not loaded by go/packages in our
// configuration. The engine therefore cannot verify whether the error
// actually embeds receiver data and falls back to its narrowing rule:
// when the body is unanalyzable AND the only return value is `error`,
// taint does NOT propagate from the receiver into the result. This kills
// the gorilla-mux noise pattern.
//
// Trade-off documented: if a stdlib method DOES happen to embed receiver
// bytes into its error string in a real exploit chain, we will miss it.
// The TestN fixture proves the principled detection still works for
// user-written validators whose bodies the engine CAN inspect.
//
// The second log call is the simpler direct flow and must still fire.
package main

import (
	"bytes"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	var buf bytes.Buffer
	if err := r.Write(&buf); err != nil {
		log.Printf("failed writing request: %v", err) // suppressed by error-only narrowing
	}

	log.Printf("query=%v", r.URL.Query().Get("q")) // want "potential log injection"
}

func main() {
	http.HandleFunc("/", handler)
	_ = http.ListenAndServe(":8080", nil)
}
