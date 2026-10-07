//go:build go1.27

package taint

import (
	"strings"
	"testing"
)

func TestIndexedDiscoveryGenericMethodSink(t *testing.T) {
	cg, pkg := detailedGraphForSource(t, `//go:build go1.27

package main
type writer struct{}
func (writer) Write[T ~string](v T) {}
func source() string { return "user" }
func main() { writer{}.Write(source()) }
`)
	var sink string
	for _, n := range cg.Nodes {
		if n.Func != nil && strings.Contains(n.Func.String(), ").Write[") {
			sink = n.Func.String()
			break
		}
	}
	if sink == "" {
		t.Fatal("generic sink instance was not built")
	}
	assertDiscoveryDiagnosticsEqual(t, cg, NewSources(pkg+".source"), NewSinks(sink), 1)
}
