package caller

import (
	"database/sql"
	"example.com/bodycoverage/helper"
	"net/http"
)

func Unsafe(r *http.Request, db *sql.DB) {
	db.Query("SELECT * FROM items WHERE name='" + helper.Identity(r.URL.Query().Get("name")) + "'")
}
func Constant(r *http.Request, db *sql.DB) {
	db.Query("SELECT * FROM items WHERE name='" + helper.Constant(r.URL.Query().Get("name")) + "'")
}
func Bound(r *http.Request, db *sql.DB) {
	db.Query("SELECT * FROM items WHERE name=?", helper.Identity(r.URL.Query().Get("name")))
}
