package main

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5"
)

func main() {
	ctx := context.Background()
	conn, _ := pgx.Connect(ctx, "")

	http.HandleFunc("/query", func(w http.ResponseWriter, r *http.Request) {
		conn.Query(ctx, r.URL.Query().Get("q")) // want "potential sql injection"
	})
	http.HandleFunc("/exec", func(w http.ResponseWriter, r *http.Request) {
		conn.Exec(ctx, r.URL.Query().Get("q")) // want "potential sql injection"
	})
	http.HandleFunc("/row", func(w http.ResponseWriter, r *http.Request) {
		conn.QueryRow(ctx, r.URL.Query().Get("q")) // want "potential sql injection"
	})
	http.HandleFunc("/prepare", func(w http.ResponseWriter, r *http.Request) {
		// Prepare is (ctx, name, sql): the SQL text is the third argument.
		conn.Prepare(ctx, "stmt", r.URL.Query().Get("q")) // want "potential sql injection"
	})
	http.HandleFunc("/safe", func(w http.ResponseWriter, r *http.Request) {
		// Parameterized: the query text is constant, user input is a bound value.
		conn.Query(ctx, "SELECT * FROM t WHERE id = $1", r.URL.Query().Get("id"))
	})
	http.HandleFunc("/safe-prepare", func(w http.ResponseWriter, r *http.Request) {
		// The statement name is user-controlled but the SQL text is constant:
		// only the SQL text is the injection channel, so this must stay clean.
		conn.Prepare(ctx, r.URL.Query().Get("name"), "SELECT 1")
	})
	http.ListenAndServe(":8080", nil)
}
