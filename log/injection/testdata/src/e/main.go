package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
)

var logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
	Level: slog.LevelInfo,
}))

func l(input string) {
	logger.InfoContext(context.Background(), "l", "input", input) // want "potential log injection"
}

func buisness(input string) {
	l(input)
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("input")

		f := func() {
			buisness(input)
		}

		f()
	})

	http.ListenAndServe(":8080", nil)
}
