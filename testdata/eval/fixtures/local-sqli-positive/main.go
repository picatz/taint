package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

func unsafeQuery(db *sql.DB, r *http.Request) {
	name := r.URL.Query().Get("name")
	q := fmt.Sprintf("SELECT * FROM users WHERE name='%s'", name)
	_, _ = db.Query(q)
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		unsafeQuery(nil, r)
	})
	_ = http.ListenAndServe(":8080", nil)
}
