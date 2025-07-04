package main

import (
	"net/http"

	"github.com/jmoiron/sqlx"
)

func main() {
	db, _ := sqlx.Open("sqlite3", ":memory:")
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		db.Queryx(r.URL.Query().Get("q")) // want "potential sql injection"
	})
	http.ListenAndServe(":8080", nil)
}
