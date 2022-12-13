package main

import (
	"database/sql"
	"net/http"
)

func business7(db *sql.DB, q string) error {
	_, err := db.Query(q) // want "potential sql injection"
	if err != nil {
		return err
	}
	return nil
}

func realMain() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/boo", func(w http.ResponseWriter, r *http.Request) {
		pass, _ := r.URL.User.Password()
		business7(db, pass)
	})
}

func main() {
	realMain()
}
