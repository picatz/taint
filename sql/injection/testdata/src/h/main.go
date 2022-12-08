package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jinzhu/gorm"
)

type User struct {
	gorm.Model `json:"model"`
	Name       string `json:"name"`
	Email      string `json:"email"`
}

func handle(db *gorm.DB, u string) {
	q := fmt.Sprintf("url='%s'", u)

	var users []User
	db.Where(q).Find(&users) // want "potential sql injection"
	fmt.Println()
}

func business(db *gorm.DB, q *string) error {
	handle(db, *q)
	return nil
}

func realMain() {
	db, _ := gorm.Open("sqlite3", ":memory:")

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var input map[string]any
		json.NewDecoder(r.Body).Decode(&input)

		func() {
			userValue := fmt.Sprintf("%s", input["query"])
			business(db, func() *string {
				return &userValue
			}())
		}()
	})
}

func main() {
	realMain()
}
