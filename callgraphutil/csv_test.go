package callgraphutil_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/picatz/taint/callgraphutil"
)

func TestWriteCSV(t *testing.T) {
	g := exportTestGraph(exportUnsortedNodeOrder)

	output := writeCSV(t, g)
	if repeated := writeCSV(t, g); output != repeated {
		t.Fatalf("WriteCSV changed across repeated calls\nfirst:\n%s\nsecond:\n%s", output, repeated)
	}
	if sortedInsertion := writeCSV(t, exportTestGraph(exportSortedNodeOrder)); output != sortedInsertion {
		t.Fatalf("WriteCSV changed with graph node insertion order\nunsorted:\n%s\nsorted:\n%s", output, sortedInsertion)
	}

	rows := readCSVRows(t, output)
	wantHeader := []string{
		"source_pkg",
		"source_pkg_go_version",
		"source_pkg_origin",
		"source_func",
		"source_func_name",
		"source_func_signature",
		"target_pkg",
		"target_pkg_go_version",
		"target_pkg_origin",
		"target_func",
		"target_func_name",
		"target_func_signature",
	}
	if len(rows) == 0 || !reflect.DeepEqual(rows[0], wantHeader) {
		t.Fatalf("unexpected CSV header: %#v", rows)
	}

	assertCSVEdges(t, rows[1:], [][2]string{
		{"aSource", "zTarget"},
		{"zSource", "aTarget"},
		{"zSource", "zTarget"},
	})
}

func TestWriteCSVReturnsFlushError(t *testing.T) {
	errFlush := errors.New("flush failed")
	err := callgraphutil.WriteCSV(errorWriter{err: errFlush}, exportTestGraph(exportUnsortedNodeOrder))
	if !errors.Is(err, errFlush) {
		t.Fatalf("expected flush error, got %v", err)
	}
}

func assertCSVEdges(t *testing.T, rows [][]string, want [][2]string) {
	t.Helper()
	if len(rows) != len(want) {
		t.Fatalf("expected %d edge rows, got %d: %#v", len(want), len(rows), rows)
	}
	for i, row := range rows {
		if len(row) != 12 {
			t.Fatalf("expected 12 columns in row %d, got %d: %#v", i, len(row), row)
		}
		got := [2]string{row[3], row[9]}
		if got != want[i] {
			t.Fatalf("row %d edge = %v, want %v", i, got, want[i])
		}
	}
}
