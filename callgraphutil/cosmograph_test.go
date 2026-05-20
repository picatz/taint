package callgraphutil_test

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/picatz/taint/callgraphutil"
)

func TestWriteCosmograph(t *testing.T) {
	g := exportTestGraph(exportUnsortedNodeOrder)

	graph, metadata := writeCosmograph(t, g)
	if repeatedGraph, repeatedMetadata := writeCosmograph(t, g); graph != repeatedGraph || metadata != repeatedMetadata {
		t.Fatalf("WriteCosmograph changed across repeated calls\ngraph first:\n%s\ngraph second:\n%s\nmetadata first:\n%s\nmetadata second:\n%s",
			graph, repeatedGraph, metadata, repeatedMetadata)
	}
	if sortedGraph, sortedMetadata := writeCosmograph(t, exportTestGraph(exportSortedNodeOrder)); graph != sortedGraph || metadata != sortedMetadata {
		t.Fatalf("WriteCosmograph changed with graph node insertion order\ngraph unsorted:\n%s\ngraph sorted:\n%s\nmetadata unsorted:\n%s\nmetadata sorted:\n%s",
			graph, sortedGraph, metadata, sortedMetadata)
	}

	wantGraphRows := [][]string{
		{"source", "target"},
		{"20", "40"},
		{"10", "30"},
		{"10", "40"},
	}
	if got := readCSVRows(t, graph); !reflect.DeepEqual(got, wantGraphRows) {
		t.Fatalf("unexpected cosmograph rows:\ngot:  %#v\nwant: %#v", got, wantGraphRows)
	}

	wantMetadataRows := [][]string{
		{"id", "pkg", "func"},
		{"20", "shared", "aSource"},
		{"30", "shared", "aTarget"},
		{"10", "shared", "zSource"},
		{"40", "shared", "zTarget"},
	}
	if got := readCSVRows(t, metadata); !reflect.DeepEqual(got, wantMetadataRows) {
		t.Fatalf("unexpected cosmograph metadata rows:\ngot:  %#v\nwant: %#v", got, wantMetadataRows)
	}
}

func TestWriteCosmographReturnsFlushErrors(t *testing.T) {
	g := exportTestGraph(exportUnsortedNodeOrder)

	graphErr := errors.New("graph flush failed")
	var metadata bytes.Buffer
	err := callgraphutil.WriteCosmograph(errorWriter{err: graphErr}, &metadata, g)
	if !errors.Is(err, graphErr) {
		t.Fatalf("expected graph flush error, got %v", err)
	}

	metadataErr := errors.New("metadata flush failed")
	var graph bytes.Buffer
	err = callgraphutil.WriteCosmograph(&graph, errorWriter{err: metadataErr}, g)
	if !errors.Is(err, metadataErr) {
		t.Fatalf("expected metadata flush error, got %v", err)
	}
}
