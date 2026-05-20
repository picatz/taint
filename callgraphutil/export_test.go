package callgraphutil_test

import (
	"bytes"
	"encoding/csv"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/picatz/taint/callgraphutil"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

var (
	exportSortedNodeOrder   = []string{"aSource", "aTarget", "zSource", "zTarget"}
	exportUnsortedNodeOrder = []string{"zTarget", "zSource", "aTarget", "aSource"}
)

type errorWriter struct {
	err error
}

func (w errorWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func exportTestGraph(nodeOrder []string) *callgraph.Graph {
	prog := ssa.NewProgram(token.NewFileSet(), ssa.InstantiateGenerics)
	sig := types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false)

	ids := map[string]int{
		"aSource": 20,
		"aTarget": 30,
		"zSource": 10,
		"zTarget": 40,
	}
	nodes := make(map[string]*callgraph.Node, len(ids))
	for _, name := range exportSortedNodeOrder {
		nodes[name] = &callgraph.Node{
			Func: prog.NewFunction(name, sig, "test"),
			ID:   ids[name],
		}
	}

	g := &callgraph.Graph{
		Root:  nodes["aSource"],
		Nodes: make(map[*ssa.Function]*callgraph.Node, len(nodes)),
	}
	for _, name := range nodeOrder {
		n := nodes[name]
		g.Nodes[n.Func] = n
	}

	callgraph.AddEdge(nodes["zSource"], nil, nodes["zTarget"])
	callgraph.AddEdge(nodes["zSource"], nil, nodes["aTarget"])
	callgraph.AddEdge(nodes["aSource"], nil, nodes["zTarget"])

	return g
}

func writeCSV(t *testing.T, g *callgraph.Graph) string {
	t.Helper()
	var buf bytes.Buffer
	if err := callgraphutil.WriteCSV(&buf, g); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func writeCosmograph(t *testing.T, g *callgraph.Graph) (string, string) {
	t.Helper()
	var graph bytes.Buffer
	var metadata bytes.Buffer
	if err := callgraphutil.WriteCosmograph(&graph, &metadata, g); err != nil {
		t.Fatal(err)
	}
	return graph.String(), metadata.String()
}

func readCSVRows(t *testing.T, output string) [][]string {
	t.Helper()
	rows, err := csv.NewReader(strings.NewReader(output)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return rows
}
