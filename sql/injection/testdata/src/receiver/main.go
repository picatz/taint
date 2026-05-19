package main

import (
	"database/sql"
	"net/http"
)

type Service struct {
	db *sql.DB
}

func (s *Service) Query(q string) {
	s.db.Query(q) // want "potential sql injection"
}

func main() {
	var svc *Service
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		svc.Query(r.URL.Query().Get("q"))
	})
}
