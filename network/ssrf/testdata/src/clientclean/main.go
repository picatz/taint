package main

import (
	"net/http"
	"net/url"
	"strings"
)

func fetch(client *http.Client, req *http.Request) {
	_, _ = client.Do(req)
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		client := &http.Client{}

		req, _ := http.NewRequest("GET", "https://example.com/health", nil)
		fetch(client, req)

		post := client.Post
		_, _ = post("https://example.com/submit", r.Header.Get("Content-Type"), strings.NewReader(r.FormValue("body")))

		postForm := client.PostForm
		_, _ = postForm("https://example.com/form", url.Values{"q": []string{r.FormValue("q")}})
	})
}
