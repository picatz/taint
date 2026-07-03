package main

import (
	"net/http"

	"custompkg"
)

func main() {
	db := &custompkg.DB{}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		db.Exec(r.URL.Query().Get("q")) // want "potential sql injection"
	})
	http.ListenAndServe(":8080", nil)
}
