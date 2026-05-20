package main

import (
	"log/slog"
	"net/http"
	"os"
)

var logger = slog.New(slog.NewTextHandler(os.Stderr, nil))

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("input")
		logger.Info("input", slog.String("value", input))                         // want "potential log injection"
		logger.Warn("input", slog.Any("value", input))                            // want "potential log injection"
		logger.Error("input", slog.Group("request", slog.String("value", input))) // want "potential log injection"
	})

	http.ListenAndServe(":8080", nil)
}
