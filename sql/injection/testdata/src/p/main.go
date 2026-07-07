package main

import (
	"fmt"
	"net/http"

	"xorm.io/xorm"
)

func business(db *xorm.Engine, q string) {
	db.Query(q) // want "potential sql injection"
	db.Where(q) // want "potential sql injection"
	db.SQL(q)   // want "potential sql injection"
}

// parameterized exercises the safe case. xorm's query parameter is interface{},
// so a constant query text is boxed in a MakeInterface. A constant query with
// the user value passed as a bound parameter (the "?" placeholder) is safe and
// must not be reported, even though the bound value is user-controlled.
func parameterized(db *xorm.Engine, userInput string) {
	db.Where("owner = ?", userInput)
	db.And("name = ?", userInput)

	// Interpolating the user value into the query text is NOT safe: it is the
	// SQL channel, not a bound parameter.
	db.Where(fmt.Sprintf("%s = 'x'", userInput)) // want "potential sql injection"
}

func main() {
	var db *xorm.Engine
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		business(db, r.URL.Query().Get("q"))
	})
	http.HandleFunc("/p", func(w http.ResponseWriter, r *http.Request) {
		parameterized(db, r.URL.Query().Get("q"))
	})
	http.ListenAndServe(":8080", nil)
}
