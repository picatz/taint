package main

import (
	"net/http"
	"github.com/jmoiron/sqlx"
)

func businessSqlx(db *sqlx.DB, q string) {
	db.Select(nil, q)    // want "potential sql injection"
	db.Get(nil, q)       // want "potential sql injection"
	db.MustExec(q)       // want "potential sql injection"
}

func run() {
	var db *sqlx.DB // assume initialized elsewhere

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		businessSqlx(db, r.URL.Query().Get("sql-query"))
	})

	http.ListenAndServe(":8080", mux)
}

func main() {
	run()
}