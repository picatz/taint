package main

import (
	"net/http"

	"k8s.io/klog/v2"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		klog.Infof("input: %s", r.URL.Query().Get("input")) // want "potential log injection"
		klog.InfoS(r.URL.Query().Get("q"), "k", "v")        // want "potential log injection"
	})

	http.ListenAndServe(":8080", nil)
}
