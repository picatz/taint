package main

import (
	"net/http"

	"xorm.io/xorm"
)

func business(db *xorm.Engine, q string) {
	db.Query(q) // want "potential sql injection"
	db.Where(q) // want "potential sql injection"
	db.SQL(q)   // want "potential sql injection"
}

func main() {
	var db *xorm.Engine
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		business(db, r.URL.Query().Get("q"))
	})
	http.ListenAndServe(":8080", nil)
}
