package main

import (
	"net/http"
)

func main() {
	client := &http.Client{}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = client.Get(r.URL.Query().Get("url")) // want "potential server-side request forgery"
	})
}
