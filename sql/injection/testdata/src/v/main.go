package main

import (
	"net/http"

	"github.com/sqreen/go-dvwa/vulnerable"
)

func main() {
	db, _ := vulnerable.PrepareSQLDB()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		vulnerable.GetProducts(r.Context(), db, r.FormValue("category"))
	})
	http.ListenAndServe(":8080", nil)
}
