package main

import (
	"log"
	"net/http"
)

func l(input string) {
	l := log.New(nil, "", 0)
	l.Println(input) // want "potential log injection"
}

func buisness(input string) {
	l(input)
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("input")

		buisness(input)
	})

	http.ListenAndServe(":8080", nil)
}
