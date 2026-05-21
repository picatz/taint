package main

import (
	"net/http"
	"os"
)

func run(r *http.Request) {
	os.Open(r.FormValue("file")) // want "potential path traversal"
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		run(r)
	})
}
