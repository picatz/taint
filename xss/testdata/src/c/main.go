package main

import (
	"bufio"
	"io"
	"net/http"
)

func buffer(r io.Reader) io.Reader {
	return bufio.NewReader(r)
}

func mirror(w http.ResponseWriter, r *http.Request) {
	_, err := io.Copy(w, buffer(r.Body)) // want "potential XSS"
	if err != nil {
		panic(err)
	}
}

func main() {
	http.HandleFunc("/", mirror)

	http.ListenAndServe(":8080", nil)
}
