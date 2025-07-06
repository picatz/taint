package main

import (
	"net/http"

	"github.com/Masterminds/squirrel"
)

func handler(w http.ResponseWriter, r *http.Request) {
	squirrel.Expr(r.URL.Query().Get("q")) // want "potential sql injection"
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8080", nil)
}
