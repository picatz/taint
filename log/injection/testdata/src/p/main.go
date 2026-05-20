package main

import (
	"fmt"
	"net/http"

	"go.uber.org/zap"
)

var logger, _ = zap.NewProduction()

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("input")
		logger.Info("input", zap.Any("value", input))                        // want "potential log injection"
		logger.Warn("input", zap.ByteString("value", []byte(input)))         // want "potential log injection"
		logger.Error("input", zap.Error(fmt.Errorf("bad input: %s", input))) // want "potential log injection"
	})

	http.ListenAndServe(":8080", nil)
}
