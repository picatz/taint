package main

import (
	"bufio"
	"html"
	"io"
	"net/http"
)

func echoSafe(w io.Writer, r any) {
	ior := r.(io.Reader)

	b, err := io.ReadAll(ior)
	if err != nil {
		panic(err)
	}

	es := html.EscapeString(string(b))

	w.Write([]byte(es))
}

func echoUnsafe(w io.Writer, r any) {
	ior := r.(io.Reader)

	b, err := io.ReadAll(ior)
	if err != nil {
		panic(err)
	}

	w.Write(b)
}

func handler(w http.ResponseWriter, r *http.Request) {
	b := bufio.NewWriterSize(w, 4096)
	defer b.Flush()

	switch r.URL.Path {
	case "/mirror-safe":
		echoSafe(w, r.Body)
	case "/mirror-unsafe":
		echoUnsafe(w, r.Body) // want "potential XSS"
	}
}

func main() {
	http.HandleFunc("/", handler)

	http.ListenAndServe(":8080", nil)
}
