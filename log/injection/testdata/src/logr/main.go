package main

import (
	"net/http"

	"github.com/go-logr/logr"
)

var logger = logr.New(nil)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logger.Info(r.URL.Query().Get("input")) // want "potential log injection"
	})

	http.ListenAndServe(":8080", nil)
}
