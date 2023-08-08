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

func mirror2(w http.ResponseWriter, r *http.Request) {
	_, err := io.WriteString(w, r.URL.Query().Get("q")) // want "potential XSS"
	if err != nil {
		panic(err)
	}
}

func mirror3(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte(r.URL.Query().Get("q"))) // want "potential XSS"
	if err != nil {
		panic(err)
	}
}

func mirror4(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	_, err = w.Write(b) // want "potential XSS"
	if err != nil {
		panic(err)
	}
}

func main() {
	http.HandleFunc("/1", mirror)
	http.HandleFunc("/2", mirror2)
	http.HandleFunc("/3", mirror3)
	http.HandleFunc("/4", mirror4)

	http.ListenAndServe(":8080", nil)
}
