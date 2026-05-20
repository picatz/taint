package main

import (
	"context"
	"database/sql"
	"net/http"
)

func execDB(db *sql.DB, q string) {
	db.Exec(q) // want "potential sql injection"
}

func execDBContext(db *sql.DB, q string) {
	db.ExecContext(context.Background(), q) // want "potential sql injection"
}

func prepareDB(db *sql.DB, q string) {
	db.Prepare(q) // want "potential sql injection"
}

func execTx(tx *sql.Tx, q string) {
	tx.ExecContext(context.Background(), q) // want "potential sql injection"
}

func prepareTx(tx *sql.Tx, q string) {
	tx.Prepare(q) // want "potential sql injection"
}

func execConn(conn *sql.Conn, q string) {
	conn.ExecContext(context.Background(), q) // want "potential sql injection"
}

func prepareConn(conn *sql.Conn, q string) {
	conn.PrepareContext(context.Background(), q) // want "potential sql injection"
}

func main() {
	var db *sql.DB
	var tx *sql.Tx
	var conn *sql.Conn
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		execDB(db, q)
		execDBContext(db, q)
		prepareDB(db, q)
		execTx(tx, q)
		prepareTx(tx, q)
		execConn(conn, q)
		prepareConn(conn, q)
	})
}
