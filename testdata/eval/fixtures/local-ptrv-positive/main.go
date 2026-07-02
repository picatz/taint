package main

import (
	"net/http"
	"os"
)

func unsafeRead(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	data, err := os.ReadFile(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	_, _ = w.Write(data)
}

func main() {
	http.HandleFunc("/", unsafeRead)
	_ = http.ListenAndServe(":8080", nil)
}
