package main

import (
	"context"
	"net/http"

	"github.com/gogf/gf/v2/database/gdb"
)

func main() {
	ctx := context.Background()
	db, _ := gdb.Instance()

	http.HandleFunc("/query", func(w http.ResponseWriter, r *http.Request) {
		db.Query(ctx, r.URL.Query().Get("q")) // want "potential sql injection"
	})
	http.HandleFunc("/raw", func(w http.ResponseWriter, r *http.Request) {
		db.Raw(r.URL.Query().Get("q")) // want "potential sql injection"
	})
	http.HandleFunc("/safe", func(w http.ResponseWriter, r *http.Request) {
		// Parameterized: constant SQL text, user input as a bound value.
		db.Query(ctx, "SELECT * FROM t WHERE id = ?", r.URL.Query().Get("id"))
	})
	http.ListenAndServe(":8080", nil)
}
