package main

import (
	"context"
	"net/http"

	"github.com/golang/glog"
)

func main() {
	ctx := context.Background()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("input")
		glog.InfoDepth(1, input)             // want "potential log injection"
		glog.InfoContext(ctx, input)         // want "potential log injection"
		glog.ErrorContextf(ctx, "%s", input) // want "potential log injection"
		glog.Exit(input)                     // want "potential log injection"
	})

	http.ListenAndServe(":8080", nil)
}
