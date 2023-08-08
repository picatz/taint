package main

import (
	"net/http"
)

func mirror(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("input")

	b := []byte(input)

	w.Write(b) // want "potential XSS"
}

func main() {
	http.HandleFunc("/", mirror)

	http.ListenAndServe(":8080", nil)
}
