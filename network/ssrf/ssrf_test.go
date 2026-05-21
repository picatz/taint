package ssrf

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

var testdata = analysistest.TestData()

func TestDirectGet(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "direct")
}

func TestNewRequest(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "newrequest")
}

func TestNetDial(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "dial")
}

func TestClientDo(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "clientdo")
}

func TestConstantsClean(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "clean")
}
