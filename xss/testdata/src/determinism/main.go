// determinism is a stability regression fixture: the writeBody helper is
// invoked from many places, only one of which is on the actual taint path.
// Before the call-site picker was changed to walk the taint path, the
// analyzer iterated cg.Nodes (a Go map) and reported the *first*
// in-package edge it saw — which flipped between runs.
//
// The analyzer must report the call on the taint path (the unsafe handler
// below) and never the unrelated calls.
package main

import "net/http"

func writeBody(w http.ResponseWriter, s string) {
	w.Write([]byte(s))
}

// Many distractor call sites of writeBody. The order in which the
// callgraph remembers these is non-deterministic without canonical sort.
func benignA(w http.ResponseWriter) { writeBody(w, "a") }
func benignB(w http.ResponseWriter) { writeBody(w, "b") }
func benignC(w http.ResponseWriter) { writeBody(w, "c") }
func benignD(w http.ResponseWriter) { writeBody(w, "d") }
func benignE(w http.ResponseWriter) { writeBody(w, "e") }

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeBody(w, r.URL.Query().Get("name")) // want "potential XSS"
	})
	// Force the distractor functions into the live callgraph.
	http.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) { benignA(w) })
	http.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) { benignB(w) })
	http.HandleFunc("/c", func(w http.ResponseWriter, r *http.Request) { benignC(w) })
	http.HandleFunc("/d", func(w http.ResponseWriter, r *http.Request) { benignD(w) })
	http.HandleFunc("/e", func(w http.ResponseWriter, r *http.Request) { benignE(w) })
}
