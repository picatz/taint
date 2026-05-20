package main

import (
	"context"
	"net/http"
	"os/exec"
)

func run(ctx context.Context, r *http.Request) {
	exec.CommandContext(ctx, r.FormValue("cmd")) // want "potential command injection"
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		run(context.Background(), r)
	})
}
