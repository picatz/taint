package main

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	ctx := context.Background()
	pool, _ := pgxpool.New(ctx, "")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		pool.Exec(ctx, r.URL.Query().Get("q")) // want "potential sql injection"
	})
	http.ListenAndServe(":8080", nil)
}
