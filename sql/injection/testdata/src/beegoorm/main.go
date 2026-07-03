package main

import (
	"context"
	"net/http"

	"github.com/beego/beego/v2/client/orm"
)

func main() {
	ctx := context.Background()
	o := orm.NewOrm()

	http.HandleFunc("/raw", func(w http.ResponseWriter, r *http.Request) {
		o.Raw(r.URL.Query().Get("q")) // want "potential sql injection"
	})
	http.HandleFunc("/rawctx", func(w http.ResponseWriter, r *http.Request) {
		o.RawWithCtx(ctx, r.URL.Query().Get("q")) // want "potential sql injection"
	})
	http.HandleFunc("/safe", func(w http.ResponseWriter, r *http.Request) {
		// Parameterized: constant SQL text, user input as a bound value.
		o.Raw("SELECT id FROM user WHERE name = ?", r.URL.Query().Get("name"))
	})
	http.ListenAndServe(":8080", nil)
}
