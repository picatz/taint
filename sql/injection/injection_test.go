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
	// t.Skip("skipping known failing test for now")
	analysistest.Run(t, testdata, Analyzer, "h")
}

func TestExample(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "example")
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

func TestM(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "m")
}

func TestGormV2(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "gormv2")
}

func TestXorm(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "xorm")
}

// TODO: Fix sqlx test - arguments are in different positions
// func TestSqlx(t *testing.T) {
// 	analysistest.Run(t, testdata, Analyzer, "sqlx")
// }
