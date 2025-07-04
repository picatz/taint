package main

import (
	"net/http"
	"xorm.io/xorm"
)

func businessXorm(db *xorm.Engine, q string) {
	db.Query(q)          // want "potential sql injection"
	db.Where(q)          // want "potential sql injection"
	db.SQL(q)            // want "potential sql injection"
}

func run() {
	var db *xorm.Engine // assume initialized elsewhere

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		businessXorm(db, r.URL.Query().Get("sql-query"))
	})

	http.ListenAndServe(":8080", mux)
}

func main() {
	run()
}