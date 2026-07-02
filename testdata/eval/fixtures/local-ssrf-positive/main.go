package main

import (
	"io"
	"net/http"
)

func unsafeFetch(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	resp, err := http.Get(url)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(w, resp.Body)
}

func main() {
	http.HandleFunc("/", unsafeFetch)
	_ = http.ListenAndServe(":8080", nil)
}
