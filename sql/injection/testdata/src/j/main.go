package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
)

func login(db *sql.DB, q string) error {
	_, err := db.Query(q) // want "potential sql injection"
	if err != nil {
		return err
	}
	return nil
}

func startServer() error {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return err
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		pass, _ := r.URL.User.Password()
		login(db, pass)
	})

	return http.ListenAndServe(":8080", mux)
}

type command struct {
	name string
	run  func(args []string) error
}

type commands []*command

func (c commands) run(args []string) error {
	for _, cmd := range c {
		if cmd.name == args[0] {
			return cmd.run(args[1:])
		}
	}

	return fmt.Errorf("unknown command: %s", args[0])
}

type cli struct {
	commands commands
}

func (c *cli) run(args []string) error {
	return c.commands.run(args)
}

func main() {
	c := &cli{
		commands{
			{
				name: "start-server",
				run: func(args []string) error {
					startServer()
					return nil
				},
			},
		},
	}

	err := c.run(os.Args[1:])
	if err != nil {
		panic(err)
	}
}
