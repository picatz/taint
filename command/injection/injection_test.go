package injection

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

var testdata = analysistest.TestData()

func TestDirectCommandName(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "direct")
}

func TestCommandContextName(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "commandcontext")
}

func TestShellCommandString(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "shell")
}

func TestTaintedOrdinaryArgumentIgnored(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "argument")
}

func TestConstantsClean(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "clean")
}
