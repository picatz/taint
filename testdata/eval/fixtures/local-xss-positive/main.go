package main

import (
	"net/http"
)

func unsafeWrite(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	w.Write([]byte("<h1>" + name + "</h1>"))
}

func main() {
	http.HandleFunc("/", unsafeWrite)
	_ = http.ListenAndServe(":8080", nil)
}
