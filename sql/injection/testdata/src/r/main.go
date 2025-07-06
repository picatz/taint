package main

import (
	"net/http"

	"github.com/rqlite/gorqlite"
)

func business(conn *gorqlite.Connection, q string) {
	conn.Write(q) // want "potential sql injection"
}

func main() {
	var c *gorqlite.Connection
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		business(c, r.URL.Query().Get("q"))
	})
	http.ListenAndServe(":8080", nil)
}
