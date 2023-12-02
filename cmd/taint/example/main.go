package main

import (
	"database/sql"
	"net/http"
)

func handle(db *sql.DB, q string) {
	db.Query(q) // want "potential sql injection"
}

func business(db *sql.DB, q *string) error {
	handle(db, *q)
	return nil
}

func main() {
	db, _ := sql.Open("sqlite3", ":memory:")

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query()["query"]
		userValue := user[0]
		business(db, &userValue)
	})

	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		panic(err)
	}
}
