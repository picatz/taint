package main

import (
	"io"
	"net/http"
)

// this will panic if run, because the given *http.Request is not an io.Reader
// but it's fine for testing, because we don't actually run the code.
func echo(w io.Writer, r any) {
	ior := r.(io.Reader)

	b, err := io.ReadAll(ior)
	if err != nil {
		panic(err)
	}

	w.Write(b)
}

func handler(w http.ResponseWriter, r *http.Request) {
	echo(w, r) // want "potential XSS"
}

func main() {
	http.HandleFunc("/mirror-safe", handler)

	http.ListenAndServe(":8080", nil)
}
