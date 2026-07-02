package main

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5"
)

func main() {
	ctx := context.Background()
	conn, _ := pgx.Connect(ctx, "")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tx, _ := conn.Begin(ctx)
		tx.Exec(ctx, r.URL.Query().Get("q")) // want "potential sql injection"
	})
	http.ListenAndServe(":8080", nil)
}
