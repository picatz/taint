package injection

import (
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

func TestI(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "i")
}

func TestJ(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "j")
}

func TestK(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "k")
}

func TestL(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "l")
}

// TestM is the gorilla-mux regression: the engine must NOT propagate taint
// into the error return of a stdlib method called on a source-typed
// receiver when the method body is unavailable for inspection. This kills
// the noise pattern from `mux_test.go:2985` while preserving detection on
// the direct r.URL.Query() flow in the same handler.
func TestM(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "m")
}

// TestN is the positive complement: a custom validator that embeds request
// data in its error value must still be flagged via the precise return
// walker. This guards against regressing to a coarse "errors are never
// tainted" heuristic.
func TestN(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "n")
}

func TestO(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "o")
}

func TestP(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "p")
}

func TestGRPC(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "grpc")
}
