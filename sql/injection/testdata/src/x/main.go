package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		defer db.Query(r.URL.Query().Get("q")) // want "potential sql injection"
	})

	http.ListenAndServe(":8080", nil)
}
