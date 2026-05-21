package pathtraversal

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

var testdata = analysistest.TestData()

func TestDirectOpen(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "direct")
}

func TestReadFile(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "readfile")
}

func TestFilepathJoin(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "join")
}

func TestServeFile(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "servefile")
}

func TestConstantsClean(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "clean")
}

func TestMapDispatch(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "mapdispatch")
}

func TestGlobalVarDispatch(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "globalvar")
}
