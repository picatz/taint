package main

import (
	"database/sql"
	"net/http"
)

func business(db *sql.DB, q string) {
	db.Query(q) // want "potential sql injection"
}

func run() {
	db, _ := sql.Open("sqlite3", ":memory:")

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		business(db, r.URL.Query().Get("sql-query"))
	})

	http.ListenAndServe(":8080", mux)
}

func main() {
	run()
}
