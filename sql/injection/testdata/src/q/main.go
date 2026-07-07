package main

import (
	"net/http"

	"github.com/go-pg/pg"
)

func business(db *pg.DB, q string) {
	db.Exec(q) // want "potential sql injection"
}

// parameterized passes the user value as a bound parameter, which is safe even
// though go-pg's query channel is interface{}.
func parameterized(db *pg.DB, userValue string) {
	db.Exec("UPDATE t SET x = 'y' WHERE id = ?", userValue)
}

func main() {
	var db *pg.DB
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		business(db, r.URL.Query().Get("q"))
	})
	http.HandleFunc("/p", func(w http.ResponseWriter, r *http.Request) {
		parameterized(db, r.URL.Query().Get("v"))
	})
	http.ListenAndServe(":8080", nil)
}
