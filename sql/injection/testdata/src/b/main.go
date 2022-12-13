package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
)

func business(db *sql.DB, name string) error {
	q := fmt.Sprintf("SELECT * FROM voo where name='%s'", name)
	_, err := db.Query(q) // want "potential sql injection"
	if err != nil {
		return err
	}
	return nil
}

func business2(db *sql.DB, name string) error {
	q := "SELECT * FROM roo where name='" + name + "'"
	_, err := db.Query(q) // want "potential sql injection"
	if err != nil {
		return err
	}
	return nil
}

func business3(db *sql.DB, query string) error {
	_, err := db.Query(query) // want "potential sql injection"
	if err != nil {
		return err
	}
	return nil
}

func business4(db *sql.DB, query string) error {
	_, err := db.Query(query)
	if err != nil {
		return err
	}
	return nil
}

type logic struct {
	name string
}

func business5(db *sql.DB, l logic) error {
	_, err := db.Query(l.name) // want "potential sql injection"
	if err != nil {
		return err
	}
	return nil
}

func business6(db *sql.DB, u url.Values) error {
	_, err := db.Query(u.Get("query")) // want "potential sql injection"
	if err != nil {
		return err
	}
	return nil
}

func business7(db *sql.DB, q string) error {
	_, err := db.Query(q) // want "potential sql injection"
	if err != nil {
		return err
	}
	return nil
}

func realMain() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		q := fmt.Sprintf("SELECT * FROM foo where nameo='%s'", r.URL.Query().Get("name"))
		rows, err := db.Query(q) // want "potential sql injection"
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte(fmt.Sprintf("%#+v", rows)))
	})

	mux.HandleFunc("/bar", func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query(fmt.Sprintf("SELECT * FROM bar where name='%s'", r.URL.Query().Get("name"))) // want "potential sql injection"
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte(fmt.Sprintf("%#+v", rows)))
	})

	mux.HandleFunc("/baz", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		business(db, name)
		business2(db, r.URL.Query().Get("name2"))
	})

	mux.HandleFunc("/boo", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("query")
		name2 := name
		business3(db, name2)

		if r.Form.Get("lol") != "" {
			business4(db, "SELECT * FROM lol where name='lol'")
		} else {
			_, err := db.Query("SELECT * FROM lol where name=?", name)
			if err != nil {
				panic(err)
			}
		}

		r.URL.User.Password()

		business5(db, logic{name: name2})

		business6(db, r.URL.Query())

		pass, _ := r.URL.User.Password()
		business7(db, pass)
	})
}

func main() {
	realMain()
}
