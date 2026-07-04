package vulndb

import (
	"slices"
	"testing"
)

func TestSymbolSinkIDs(t *testing.T) {
	tests := []struct {
		pkg    string
		symbol string
		want   []SinkID
	}{
		{
			pkg:    "golang.org/x/text/language",
			symbol: "Parse",
			want:   []SinkID{"golang.org/x/text/language.Parse"},
		},
		{
			pkg:    "crypto/elliptic",
			symbol: "p256SubInternal",
			want:   []SinkID{"crypto/elliptic.p256SubInternal"},
		},
		{
			pkg:    "example.com/db",
			symbol: "Conn.Query",
			want: []SinkID{
				"(example.com/db.Conn).Query",
				"(*example.com/db.Conn).Query",
			},
		},
	}
	for _, tt := range tests {
		got := SymbolSinkIDs(tt.pkg, tt.symbol)
		if !slices.Equal(got, tt.want) {
			t.Errorf("SymbolSinkIDs(%q, %q) = %v, want %v", tt.pkg, tt.symbol, got, tt.want)
		}
	}
}

func TestPackageSinkIDs(t *testing.T) {
	withSymbols := Import{Path: "example.com/db", Symbols: []string{"Query", "Conn.Exec"}}
	got := PackageSinkIDs(withSymbols)
	want := []SinkID{
		"example.com/db.Query",
		"(example.com/db.Conn).Exec",
		"(*example.com/db.Conn).Exec",
	}
	if !slices.Equal(got, want) {
		t.Errorf("PackageSinkIDs(withSymbols) = %v, want %v", got, want)
	}

	wholePackage := Import{Path: "example.com/db"}
	if ids := PackageSinkIDs(wholePackage); ids != nil {
		t.Errorf("PackageSinkIDs(wholePackage) = %v, want nil", ids)
	}
	if !wholePackage.IsWholePackage() {
		t.Error("symbol-less import should report IsWholePackage")
	}
	if withSymbols.IsWholePackage() {
		t.Error("import with symbols should not report IsWholePackage")
	}
}
