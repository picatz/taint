package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
)

func l(logger *slog.Logger, input string) {
	logger2 := logger.With("input", input).WithGroup("l") // want "potential log injection"

	logger2.InfoContext(context.Background(), "l", "input", []string{input}) // want "potential log injection"
}

func buisness(logger *slog.Logger, input string) {
	l(logger, input)
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("input")

		f := func() {
			buisness(logger, input)
		}

		f()
	})

	http.ListenAndServe(":8080", nil)
}
