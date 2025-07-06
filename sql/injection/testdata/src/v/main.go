package v

import (
	"database/sql"
	"net/http"
	"v/nested"
)

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		nested.Run(db, r.URL.Query().Get("name"))
	})

	http.ListenAndServe(":8080", mux)
}
