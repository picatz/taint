package main

import (
	"html"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		escaped := html.EscapeString(r.URL.Query().Get("safe"))
		_ = escaped
		w.Write([]byte(r.URL.Query().Get("unsafe"))) // want "potential XSS"
	})
}
