package main

import (
	"net"
	"net/http"
	"time"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		addr := r.URL.Query().Get("addr")
		_, _ = net.Dial("tcp", addr)                          // want "potential server-side request forgery"
		_, _ = net.DialTimeout("tcp", addr, 5*time.Second) // want "potential server-side request forgery"
	})
}
