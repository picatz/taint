package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		defer log.Println(r.URL.Query().Get("input")) // want "potential log injection"
	})

	http.ListenAndServe(":8080", nil)
}
