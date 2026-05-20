package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("input")
		fmt.Fprint(w, input)        // want "potential XSS"
		fmt.Fprintf(w, "%s", input) // want "potential XSS"
		fmt.Fprintln(w, input)      // want "potential XSS"
	})

	http.ListenAndServe(":8080", nil)
}
