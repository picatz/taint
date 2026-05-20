package main

import (
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, r.URL.Query().Get("input"), http.StatusBadRequest) // want "potential XSS"
	})

	http.ListenAndServe(":8080", nil)
}
