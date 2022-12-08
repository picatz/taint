package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
)

/*
o.business
0:
        [*ssa.Alloc          ] t0 = new [1]any (varargs)
        [*ssa.IndexAddr      ] t1 = &t0[0:int]
        [*ssa.MakeInterface  ] t2 = make any <- string (name)
        [*ssa.Store          ] *t1 = t2
        [*ssa.Slice          ] t3 = slice t0[:]
        [*ssa.Call           ] t4 = fmt.Sprintf("SELECT * FROM foo...":string, t3...)
        [*ssa.Call           ] t5 = (*database/sql.DB).Query(db, t4, nil:[]any...)
        [*ssa.Extract        ] t6 = extract t5 #0
        [*ssa.Extract        ] t7 = extract t5 #1
        [*ssa.BinOp          ] t8 = t7 != nil:error
        [*ssa.If             ] if t8 goto 1 else 2
1:
        [*ssa.Return         ] return t7
2:
        [*ssa.Return         ] return nil:error
*/
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
