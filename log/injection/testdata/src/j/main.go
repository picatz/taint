package main

import (
	"github.com/sirupsen/logrus"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logrus.Info(r.URL.Query().Get("input")) // want "potential log injection"
	})

	http.ListenAndServe(":8080", nil)
}
