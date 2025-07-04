package main

import (
	"net/http"
	// Notice: no SQL packages imported
)

func businessNoSQL(userInput string) {
	// This should not be analyzed since no SQL packages are imported
	// Even though we have a function that looks like it could be vulnerable
	_ = userInput
}

func run() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		businessNoSQL(r.URL.Query().Get("sql-query"))
	})

	http.ListenAndServe(":8080", mux)
}

func main() {
	run()
}