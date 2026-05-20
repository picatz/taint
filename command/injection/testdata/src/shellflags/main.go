package main

import (
	"net/http"
	"os/exec"
)

const shellConst = "sh"

func run(r *http.Request) {
	cmd := r.FormValue("cmd")
	exec.Command("bash", "-lc", cmd) // want "potential command injection"
	exec.Command("sh", "-ec", cmd)   // want "potential command injection"

	shell := shellConst
	exec.Command(shell, "-c", cmd) // want "potential command injection"

	args := []string{"-c", cmd}
	exec.Command("sh", args...) // want "potential command injection"
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		run(r)
	})
}
