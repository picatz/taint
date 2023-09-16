package main

import (
	"fmt"
	"io"
	"net/http"
)

func echo(w io.Writer, r any) error {
	ior, ok := r.(io.Reader)
	if !ok {
		return fmt.Errorf("failed to cast to io.Reader")
	}

	b, err := io.ReadAll(ior)
	if err != nil {
		return fmt.Errorf("failed to read all bytes from io.Reader: %w", err)
	}

	w.Write(b)

	return nil
}

func handler(w http.ResponseWriter, r *http.Request) {
	err := echo(w, r) // want "potential XSS"
	if err != nil {
		panic(err)
	}
}

func main() {
	http.HandleFunc("/mirror-safe", handler)

	http.ListenAndServe(":8080", nil)
}
