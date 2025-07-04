package main

import (
	"net/http"

	"github.com/go-pg/pg"
)

func business(db *pg.DB, q string) {
	db.Exec(q) // want "potential sql injection"
}

func main() {
	var db *pg.DB
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		business(db, r.URL.Query().Get("q"))
	})
	http.ListenAndServe(":8080", nil)
}
