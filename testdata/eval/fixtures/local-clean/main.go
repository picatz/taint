package main

import (
	"database/sql"
	"log"
	"net/http"
	"os/exec"
)

func safeQuery(db *sql.DB, r *http.Request) {
	name := r.URL.Query().Get("name")
	_, _ = db.Query("SELECT * FROM users WHERE name=?", name)
}

func safeLog() {
	log.Println("startup ok")
}

func safeCommand(r *http.Request) {
	_ = exec.Command("grep", r.FormValue("name"), "/tmp/users.txt")
}

func main() {
	safeLog()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		safeQuery(nil, r)
		safeCommand(r)
		w.Write([]byte("ok"))
	})
	_ = http.ListenAndServe(":8080", nil)
}
