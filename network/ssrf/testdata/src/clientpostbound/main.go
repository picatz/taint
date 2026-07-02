package main

import (
	"net/http"
	"net/url"
	"strings"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		client := &http.Client{}

		post := client.Post
		_, _ = post(r.URL.Query().Get("url"), "text/plain", strings.NewReader("body")) // want "potential server-side request forgery"

		postForm := client.PostForm
		_, _ = postForm(r.FormValue("url"), url.Values{"q": []string{"safe"}}) // want "potential server-side request forgery"
	})
}
