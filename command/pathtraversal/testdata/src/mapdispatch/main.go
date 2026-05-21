package main

import (
	"net/http"
	"os"
)

func openHandler(w http.ResponseWriter, r *http.Request) {
	os.Open(r.URL.Query().Get("file")) // want "potential path traversal"
}

var handlers = map[string]func(http.ResponseWriter, *http.Request){
	"/open": openHandler,
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if h, ok := handlers[r.URL.Path]; ok {
			h(w, r)
		}
	})
}
