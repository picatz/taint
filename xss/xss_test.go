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

// TestI is the chi-mirror regression: a helper that writes constants into
// a non-ResponseWriter destination (*bytes.Buffer) MUST NOT fire even
// though the surrounding handler receives an *http.Request. A direct
// w.Write on the same handler must still fire.
func TestI(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "i")
}

// TestJ ensures the destination-provenance walker classifies channel
// receives as provUnknown — preserving the diagnostic on opaque flows.
func TestJ(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "j")
}

// TestK ensures the destination-provenance walker does NOT suppress writes
// when the destination is a *bufio.Writer wrapping an http.ResponseWriter —
// a common legitimate buffering idiom that is still a real XSS vector.
func TestK(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "k")
}

func TestL(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "l")
}

func TestM(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "m")
}

// TestDeterminism runs the analyzer multiple times on a fixture with many
// in-package callers of a helper that itself writes to ResponseWriter. The
// reported position must stay on the actual taint path each run; before
// the call-site picker walked the taint path, this case would flap between
// runs because cg.Nodes map iteration is randomized.
func TestDeterminism(t *testing.T) {
	for i := range 10 {
		t.Run(fmt.Sprintf("iter-%d", i), func(t *testing.T) {
			analysistest.Run(t, testdata, Analyzer, "determinism")
		})
	}
}
