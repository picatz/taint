package main

import (
	"net/http"

	"github.com/go-gorm/gorm"
)

type User struct {
	gorm.Model
	Name string
}

func handle(db *gorm.DB, q string) {
	db.Where(q).Find(&User{}) // want "potential sql injection"
}

func main() {
	var db *gorm.DB
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handle(db, r.URL.Query().Get("q"))
	})
	http.ListenAndServe(":8080", nil)
}
