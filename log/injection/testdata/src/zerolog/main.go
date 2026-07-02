package main

import (
	"net/http"
	"os"

	"github.com/rs/zerolog"
)

var logger = zerolog.New(os.Stdout)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logger.Info().Msg(r.URL.Query().Get("input"))           // want "potential log injection"
		logger.Warn().Msgf("input: %s", r.URL.Query().Get("q")) // want "potential log injection"
	})

	http.ListenAndServe(":8080", nil)
}
