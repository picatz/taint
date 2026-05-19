package main

import (
	"database/sql"
	"net/http"
)

func dead(db *sql.DB, r *http.Request) {
	db.Query(r.URL.Query().Get("q"))
}

func main() {}
