package main

import (
	"database/sql"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db, _ := sql.Open("sqlite3", ":memory:")
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		db.Query(r.URL.Query().Get("q")) // want "potential sql injection"
	})
	http.ListenAndServe(":8080", nil)
}
