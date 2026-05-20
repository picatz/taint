package main

import (
	"context"
	"net/http"
	"os/exec"
)

func run(r *http.Request) {
	cmd := r.FormValue("cmd")
	exec.Command("sh", "-c", cmd)                              // want "potential command injection"
	exec.CommandContext(context.Background(), "sh", "-c", cmd) // want "potential command injection"
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		run(r)
	})
}
