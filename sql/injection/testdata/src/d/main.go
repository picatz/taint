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

func realMain() {
	db, _ := sql.Open("sqlite3", ":memory:")

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query()["query"]
		func() {
			userValue := user[0]
			business(db, func() *string {
				return &userValue
			}())
		}()
	})
}

func main() {
	realMain()
}
