package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
)

// login authenticates a user using a SQL query. This is intentionally vulnerable for demonstration.
func login(db *sql.DB, username, password string) error {
	query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, password)
	_, err := db.Query(query) // want "potential sql injection"
	if err != nil {
		return err
	}
	return nil
}

// startServer starts an HTTP server with a login endpoint.
func startServer() error {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return err
	}
	defer db.Close()

	// Create a users table for demonstration
	_, err = db.Exec(`CREATE TABLE users (username TEXT, password TEXT)`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO users (username, password) VALUES ('admin', 'secret')`)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		username := r.FormValue("username")
		password := r.FormValue("password")
		err := login(db, username, password)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Login failed"))
			return
		}
		w.Write([]byte("Login successful"))
	})

	return http.ListenAndServe(":8080", mux)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "start-server" {
		if err := startServer(); err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Println("Usage: m start-server")
	}
}
