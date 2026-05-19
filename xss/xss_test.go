package xss

import (
	"fmt"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

var testdata = analysistest.TestData()

func TestA(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "a")
}

func TestB(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "b")
}

func TestC(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "c")
}

func TestD(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "d")
}

func TestE(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "e")
}

func TestF(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "f")
}

func TestG(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "g")
}

func TestH(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "h")
}

// TestDeterminism runs the analyzer multiple times on a fixture with many
// in-package callers of a helper that itself writes to ResponseWriter. The
// reported position must stay on the actual taint path each run; before
// the call-site picker walked the taint path, this case would flap between
// runs because cg.Nodes map iteration is randomized.
func TestDeterminism(t *testing.T) {
	for i := 0; i < 10; i++ {
		t.Run(fmt.Sprintf("iter-%d", i), func(t *testing.T) {
			analysistest.Run(t, testdata, Analyzer, "determinism")
		})
	}
}
