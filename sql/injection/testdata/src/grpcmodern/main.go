package main

import "database/sql"

type Request struct {
	Query string
}

func (*Request) ProtoReflect() any { return nil }

func handle(db *sql.DB, req *Request) {
	db.Query(req.Query) // want "potential sql injection"
}

func main() {
	var db *sql.DB
	handle(db, &Request{})
}
