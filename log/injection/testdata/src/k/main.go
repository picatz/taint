package main

import (
	"go.uber.org/zap"
	"net/http"
)

var logger, _ = zap.NewProduction()

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logger.Info("input", zap.String("value", r.URL.Query().Get("input"))) // want "potential log injection"
	})

	http.ListenAndServe(":8080", nil)
}
