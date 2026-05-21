package main

import (
	"net/http"
	"os"
)

var dispatch func(http.ResponseWriter, *http.Request)

func openHandler(w http.ResponseWriter, r *http.Request) {
	os.Open(r.URL.Query().Get("file")) // want "potential path traversal"
}

func init() {
	dispatch = openHandler
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		dispatch(w, r)
	})
}
