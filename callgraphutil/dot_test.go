package callgraphutil_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/picatz/taint/callgraphutil"
	"golang.org/x/tools/go/callgraph"
)

func TestWriteDOT(t *testing.T) {
	output := writeDOT(t, exportTestGraph(exportUnsortedNodeOrder))
	if repeated := writeDOT(t, exportTestGraph(exportUnsortedNodeOrder)); output != repeated {
		t.Fatalf("WriteDOT changed across repeated calls\nfirst:\n%s\nsecond:\n%s", output, repeated)
	}
	if sortedInsertion := writeDOT(t, exportTestGraph(exportSortedNodeOrder)); output != sortedInsertion {
		t.Fatalf("WriteDOT changed with graph node insertion order\nunsorted:\n%s\nsorted:\n%s", output, sortedInsertion)
	}

	for _, want := range []string{
		"digraph callgraph {",
		"20 -> 40;",
		"10 -> 30;",
		"10 -> 40;",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("DOT output missing %q:\n%s", want, output)
		}
	}
}

func TestWriteDOTReturnsFlushError(t *testing.T) {
	errFlush := errors.New("flush failed")
	err := callgraphutil.WriteDOT(errorWriter{err: errFlush}, exportTestGraph(exportUnsortedNodeOrder))
	if !errors.Is(err, errFlush) {
		t.Fatalf("expected flush error, got %v", err)
	}
}

func writeDOT(t *testing.T, cg *callgraph.Graph) string {
	t.Helper()
	var output bytes.Buffer
	if err := callgraphutil.WriteDOT(&output, cg); err != nil {
		t.Fatal(err)
	}
	return output.String()
}
