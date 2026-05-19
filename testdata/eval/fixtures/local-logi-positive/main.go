package main

import (
	"log"
	"net/http"
)

func unsafeLog(r *http.Request) {
	name := r.URL.Query().Get("name")
	log.Printf("user=%s", name)
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		unsafeLog(r)
	})
	_ = http.ListenAndServe(":8080", nil)
}
