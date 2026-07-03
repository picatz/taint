package main

import (
	"net/http"
	"os"

	"github.com/go-kit/log"
)

var logger = log.NewLogfmtLogger(os.Stdout)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logger.Log("msg", "request", "input", r.URL.Query().Get("input")) // want "potential log injection"
	})

	http.ListenAndServe(":8080", nil)
}
