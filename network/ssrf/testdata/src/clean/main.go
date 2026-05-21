package main

import (
	"context"
	"net"
	"net/http"
	"time"
)

const fixedURL = "https://example.com/health"

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_ = r
		_, _ = http.Get(fixedURL)
		_, _ = http.NewRequestWithContext(context.Background(), "GET", fixedURL, nil)
		_, _ = net.DialTimeout("tcp", "example.com:443", 5*time.Second)
	})
}
