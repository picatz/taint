package main

import (
	"net/http"
	"os/exec"
)

func run(r *http.Request) {
	exec.Command(r.FormValue("cmd")) // want "potential command injection"
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		run(r)
	})
}
