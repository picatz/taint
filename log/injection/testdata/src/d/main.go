package main

import (
	"log/slog"
	"net/http"
)

func l(input string) {
	slog.Info(input) // want "potential log injection"
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
