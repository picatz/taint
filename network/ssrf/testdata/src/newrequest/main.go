package main

import (
	"context"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = http.NewRequest("GET", r.URL.Query().Get("url"), nil)                     // want "potential server-side request forgery"
		_, _ = http.NewRequestWithContext(context.Background(), "GET", r.FormValue("u"), nil) // want "potential server-side request forgery"
	})
}
