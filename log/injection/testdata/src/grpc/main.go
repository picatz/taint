package main

import (
	"context"
	"log"
)

type Request struct{ Msg string }

func (*Request) ProtoMessage() {}

type Server struct{}

func (s *Server) Handle(ctx context.Context, req *Request) {
	log.Println(req.Msg) // want "potential log injection"
}

func main() {
	srv := &Server{}
	srv.Handle(context.Background(), &Request{})
}
