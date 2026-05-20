package main

import (
	"net/http"
	"os/exec"
)

func run(r *http.Request) {
	args := []string{r.FormValue("pattern")}
	exec.Command("grep", args...)
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		run(r)
	})
}
