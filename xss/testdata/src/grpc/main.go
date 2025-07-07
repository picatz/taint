package main

import (
	"net/http"
)

type Request struct{ Input string }

func (*Request) ProtoMessage() {}

type Server struct{}

func (s *Server) Handle(w http.ResponseWriter, req *Request) {
	w.Write([]byte(req.Input)) // want "potential XSS"
}

func main() {
	srv := &Server{}
	srv.Handle(nil, &Request{})
}
