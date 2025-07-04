package main

import (
	"net/http"
	"gorm.io/gorm"
)

func businessGormV2(db *gorm.DB, q string) {
	db.Where(q)    // want "potential sql injection"
	db.Raw(q)      // want "potential sql injection"
	db.Select(q)   // want "potential sql injection"
}

func run() {
	var db *gorm.DB // assume initialized elsewhere

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		businessGormV2(db, r.URL.Query().Get("sql-query"))
	})

	http.ListenAndServe(":8080", mux)
}

func main() {
	run()
}