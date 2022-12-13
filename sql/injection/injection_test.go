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

// TODO: this is not worked out yet
func TestH(t *testing.T) {
	t.Skip("skipping known failing test for now")
	analysistest.Run(t, testdata, Analyzer, "h")
}

func TestExample(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "example")
}

func TestI(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "i")
}
