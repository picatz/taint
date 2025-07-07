package main

import (
	"context"
	"database/sql"
)

type Request struct{ Query string }

func (*Request) ProtoMessage() {}

type Server struct{}

func (s *Server) Handle(ctx context.Context, db *sql.DB, req *Request) {
	db.Query(req.Query) // want "potential sql injection"
}

func main() {
	db, _ := sql.Open("sqlite3", ":memory:")
	srv := &Server{}
	srv.Handle(context.Background(), db, &Request{})
}
