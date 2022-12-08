package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

func handle(db *sql.DB, u string) {
	q := fmt.Sprintf("SELECT * FROM voo where url='%s'", u)
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
		u := r.URL
		func() {
			userValue := fmt.Sprintf("%s", u)
			business(db, func() *string {
				return &userValue
			}())
		}()
	})
}

func main() {
	realMain()
}
