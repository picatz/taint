package main

import (
	"database/sql"
	"net/http"
)

func constant(q string) string {
	return "SELECT 1"
}

func main() {
	var db *sql.DB
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		db.Query(constant(r.URL.Query().Get("q")))
	})
}
