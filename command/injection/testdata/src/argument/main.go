package main

import (
	"net/http"
	"os/exec"
)

func run(r *http.Request) {
	exec.Command("grep", r.FormValue("pattern"), "/tmp/file")
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		run(r)
	})
}
