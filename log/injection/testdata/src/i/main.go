package main

import (
	"github.com/hashicorp/go-hclog"
	"net/http"
)

var logger = hclog.New(&hclog.LoggerOptions{})

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logger.Info("input", "value", r.URL.Query().Get("input")) // want "potential log injection"
	})

	http.ListenAndServe(":8080", nil)
}
