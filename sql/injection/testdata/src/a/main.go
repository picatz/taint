package main

import (
	"database/sql"
	"os"
)

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	rows, err := db.Query("SELECT * FROM foo where name=?", os.Args[1])
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
