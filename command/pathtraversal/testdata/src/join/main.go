package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// filepath.Join propagates taint; the path-traversal sanitizer
		// pattern (Clean + prefix check) is not modeled here, so the
		// finding should still fire.
		full := filepath.Join("/var/data", r.URL.Query().Get("name"))
		_, _ = os.Open(full) // want "potential path traversal"
	})
}
