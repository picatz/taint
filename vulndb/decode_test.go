package vulndb

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// failingReader returns some bytes then a non-EOF error, to exercise the
// read-error path.
type failingReader struct {
	data []byte
	err  error
}

func (f *failingReader) Read(p []byte) (int, error) {
	if len(f.data) > 0 {
		n := copy(p, f.data)
		f.data = f.data[n:]
		return n, nil
	}
	return 0, f.err
}

func TestDecodeJSON(t *testing.T) {
	type doc struct {
		A int    `json:"a"`
		B string `json:"b"`
	}

	t.Run("valid document", func(t *testing.T) {
		var d doc
		if err := decodeJSON(strings.NewReader(`{"a":1,"b":"x"}`), 1024, &d); err != nil {
			t.Fatal(err)
		}
		if d.A != 1 || d.B != "x" {
			t.Fatalf("decoded %+v", d)
		}
	})

	t.Run("ignores unknown fields", func(t *testing.T) {
		var d doc
		if err := decodeJSON(strings.NewReader(`{"a":1,"unknown":true,"b":"y"}`), 1024, &d); err != nil {
			t.Fatal(err)
		}
		if d.A != 1 || d.B != "y" {
			t.Fatalf("decoded %+v", d)
		}
	})

	t.Run("trailing whitespace allowed", func(t *testing.T) {
		var d doc
		if err := decodeJSON(strings.NewReader("{\"a\":1}\n\t  \n"), 1024, &d); err != nil {
			t.Fatalf("trailing whitespace should be allowed: %v", err)
		}
	})

	t.Run("trailing garbage rejected", func(t *testing.T) {
		var d doc
		err := decodeJSON(strings.NewReader(`{"a":1} garbage`), 1024, &d)
		if err == nil || !strings.Contains(err.Error(), "trailing") {
			t.Fatalf("err = %v, want trailing-data error", err)
		}
	})

	t.Run("second document rejected", func(t *testing.T) {
		var d doc
		err := decodeJSON(strings.NewReader(`{"a":1}{"a":2}`), 1024, &d)
		if err == nil {
			t.Fatal("expected error for concatenated documents")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		var d doc
		err := decodeJSON(strings.NewReader(""), 1024, &d)
		if err == nil || !strings.Contains(err.Error(), "empty") {
			t.Fatalf("err = %v, want empty-response error", err)
		}
	})

	t.Run("malformed json", func(t *testing.T) {
		var d doc
		if err := decodeJSON(strings.NewReader(`{"a":`), 1024, &d); err == nil {
			t.Fatal("expected error for malformed json")
		}
	})

	t.Run("oversized document", func(t *testing.T) {
		// A valid but large document past the limit.
		big := `{"b":"` + strings.Repeat("x", 500) + `"}`
		var d doc
		err := decodeJSON(strings.NewReader(big), 64, &d)
		if !errors.Is(err, ErrResponseTooLarge) {
			t.Fatalf("err = %v, want ErrResponseTooLarge", err)
		}
	})

	t.Run("document exactly at limit", func(t *testing.T) {
		payload := `{"a":1}` // 7 bytes
		var d doc
		if err := decodeJSON(strings.NewReader(payload), int64(len(payload)), &d); err != nil {
			t.Fatalf("a document exactly at the limit must decode: %v", err)
		}
	})

	t.Run("oversized by trailing garbage", func(t *testing.T) {
		// The value is small but the input as a whole blows the limit.
		input := `{"a":1}` + strings.Repeat(" x", 500)
		var d doc
		if err := decodeJSON(strings.NewReader(input), 32, &d); err == nil {
			t.Fatal("expected an error for oversized-with-trailing input")
		}
	})

	t.Run("read error surfaced", func(t *testing.T) {
		var d doc
		sentinel := errors.New("boom")
		err := decodeJSON(&failingReader{data: []byte(`{"a":`), err: sentinel}, 1024, &d)
		if err == nil {
			t.Fatal("expected the read error to surface")
		}
	})
}

// TestDecodeJSONStreamsAndBounds proves decodeJSON stops at the byte limit
// rather than reading an unbounded input to completion. The reader emits a
// valid-but-never-terminated JSON array, so the decoder keeps consuming until
// the budget is exhausted; a correct implementation returns ErrResponseTooLarge
// instead of looping forever.
func TestDecodeJSONStreamsAndBounds(t *testing.T) {
	var d any
	err := decodeJSON(&unterminatedArray{}, 4096, &d)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("err = %v, want ErrResponseTooLarge (bounded read)", err)
	}
}

// unterminatedArray yields "[1,1,1,..." forever: valid JSON so far, never
// closed, so a decoder reads until it runs out of budget.
type unterminatedArray struct{ started bool }

func (u *unterminatedArray) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	i := 0
	if !u.started {
		p[0] = '['
		u.started = true
		i = 1
	}
	for ; i+1 < len(p); i += 2 {
		p[i] = '1'
		p[i+1] = ','
	}
	return i, nil
}

var _ io.Reader = (*unterminatedArray)(nil)
