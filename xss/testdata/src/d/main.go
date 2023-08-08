package main

import (
	"html"
	"io"
	"net/http"
)

func mirrorSafe(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	str := html.EscapeString(string(b))

	_, err = w.Write([]byte(str)) // safe
	if err != nil {
		panic(err)
	}
}

func main() {
	http.HandleFunc("/mirror-safe", mirrorSafe)

	http.ListenAndServe(":8080", nil)
}
