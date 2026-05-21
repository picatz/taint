package main

import (
	"net/http"
	"os"
)

const fixedPath = "/etc/hostname"

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_ = r
		_, _ = os.Open(fixedPath)
		_, _ = os.ReadFile("/etc/passwd")
		_ = os.Remove("/tmp/old.log")
	})
}
