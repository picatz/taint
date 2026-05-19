// Positive regression for the precise-return-walker work.
//
// A custom helper returns an error built from request-derived data
// (fmt.Errorf with the user's query string). The precise walker must trace
// the formatted string back to the source and the log call MUST fire.
//
// This is the case the prior plan's "skip propagation when return type is
// error" heuristic would have missed; the precise walker catches it.
package main

import (
	"fmt"
	"log"
	"net/http"
)

func validate(in string) error {
	if len(in) > 100 {
		return fmt.Errorf("query too long: %s", in)
	}
	return nil
}

func handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if err := validate(q); err != nil {
		log.Printf("validate failed: %v", err) // want "potential log injection"
	}
}

func main() {
	http.HandleFunc("/", handler)
	_ = http.ListenAndServe(":8080", nil)
}
