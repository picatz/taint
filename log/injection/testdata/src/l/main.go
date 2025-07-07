package main

import (
	"github.com/golang/glog"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		glog.V(2).Info(r.URL.Query().Get("input")) // want "potential log injection"
	})

	http.ListenAndServe(":8080", nil)
}
