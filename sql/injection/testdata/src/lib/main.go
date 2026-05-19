package lib

import (
	"database/sql"
	"net/http"
)

func Handler(db *sql.DB, r *http.Request) {
	db.Query(r.URL.Query().Get("q")) // want "potential sql injection"
}
