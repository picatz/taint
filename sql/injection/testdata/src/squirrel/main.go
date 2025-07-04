package main

import (
	"net/http"
	"github.com/Masterminds/squirrel"
)

func businessSquirrel(userInput string) {
	squirrel.Expr(userInput) // want "potential sql injection"
}

func run() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		businessSquirrel(r.URL.Query().Get("sql-query"))
	})

	http.ListenAndServe(":8080", mux)
}

func main() {
	run()
}