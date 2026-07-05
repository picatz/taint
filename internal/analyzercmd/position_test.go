package analyzercmd

import "testing"

func TestSplitPosition(t *testing.T) {
	tests := []struct {
		pos  string
		path string
		line int
		col  int
	}{
		{"main.go:12:5", "main.go", 12, 5},
		{"main.go:12", "main.go", 12, 0},
		{"main.go", "main.go", 0, 0},
		{"/abs/dir/file.go:7:14", "/abs/dir/file.go", 7, 14},
		{`C:\x\y.go:10:5`, `C:\x\y.go`, 10, 5},
		{`C:\x\y.go:10`, `C:\x\y.go`, 10, 0},
		{`C:\x\y.go`, `C:\x\y.go`, 0, 0},
		{"", "", 0, 0},
		{"-", "-", 0, 0},
		{"a:b:c", "a:b:c", 0, 0},
		{"file.go:", "file.go:", 0, 0},
	}
	for _, tt := range tests {
		path, line, col := SplitPosition(tt.pos)
		if path != tt.path || line != tt.line || col != tt.col {
			t.Errorf("SplitPosition(%q) = (%q, %d, %d), want (%q, %d, %d)",
				tt.pos, path, line, col, tt.path, tt.line, tt.col)
		}
	}
}
