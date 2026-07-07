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

func TestN(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "n")
}

func TestO(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "o")
}

func TestP(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "p")
}

func TestQ(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "q")
}

func TestR(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "r")
}

func TestS(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "s")
}

func TestT(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "t")
}

func TestU(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "u")
}

func TestV(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "v")
}

func TestW(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "w")
}

func TestX(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "x")
}

func TestY(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "y")
}

func TestReceiver(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "receiver")
}

func TestConstReturn(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "constreturn")
}

func TestLibraryPackage(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "lib")
}

func TestGRPC(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "grpc")
}

func TestGRPCModern(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "grpcmodern")
}

func TestPgxConn(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "pgxconn")
}

func TestPgxPool(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "pgxpoolusage")
}

func TestPgxTx(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "pgxtx")
}

func TestBeegoORM(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "beegoorm")
}

func TestBeegoController(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "beegoctl")
}

func TestGoFrameGDB(t *testing.T) {
	analysistest.Run(t, testdata, Analyzer, "gogfgdb")
}

// TestModelsFlag exercises the -models CLI flag end to end: a user-supplied
// model marks (*custompkg.DB).Exec as a sink, and the fixture that imports
// custompkg is flagged even though the built-in rules do not cover it.
func TestModelsFlag(t *testing.T) {
	if err := Analyzer.Flags.Set("models", "testdata/models/custom.yaml"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Analyzer.Flags.Set("models", "") })
	analysistest.Run(t, testdata, Analyzer, "custommodel")
}
