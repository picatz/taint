package main

import (
	"io"
	"net/http"
)

func echo(w io.Writer, r any) {
	ior := r.(io.Reader)

	b, err := io.ReadAll(ior)
	if err != nil {
		panic(err)
	}

	w.Write(b)
}

func handler(w http.ResponseWriter, r *http.Request) {
	echo(w, r.Body) // want "potential XSS"
}

func main() {
	http.HandleFunc("/mirror-safe", handler)

	http.ListenAndServe(":8080", nil)
}
