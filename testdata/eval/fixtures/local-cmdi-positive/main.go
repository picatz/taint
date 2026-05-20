package main

import (
	"net/http"
	"os/exec"
)

func unsafeCommand(r *http.Request) {
	name := r.FormValue("cmd")
	_ = exec.Command(name)
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		unsafeCommand(r)
	})
	_ = http.ListenAndServe(":8080", nil)
}
