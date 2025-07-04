package main

import (
	"fmt"
	"net/http"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
}

func handle(db *gorm.DB, u string) {
	q := fmt.Sprintf("name='%s'", u)
	var users []User
	db.Where(q).Find(&users) // want "potential sql injection"
}

func main() {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handle(db, r.URL.Query().Get("u"))
	})
	http.ListenAndServe(":8080", nil)
}
