package main

import (
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = http.Get(r.URL.Query().Get("url")) // want "potential server-side request forgery"
	})
}
