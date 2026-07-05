package httpx

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// roundTripFunc adapts a function to a RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// newTestClient builds a client with the given base transport and instant,
// non-blocking backoff so tests do not actually wait.
func newTestClient(base http.RoundTripper, maxRetries int) *http.Client {
	c := New(WithTransport(base), WithRetry(maxRetries, time.Millisecond, time.Millisecond))
	// Replace the sleep with a no-op that still honors context cancellation.
	if rt, ok := c.Transport.(*retryTransport); ok {
		rt.sleep = func(req *http.Request, _ time.Duration) error { return req.Context().Err() }
	}
	return c
}

func TestRetriesTransientStatusThenSucceeds(t *testing.T) {
	var calls atomic.Int64
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		n := calls.Add(1)
		code := http.StatusServiceUnavailable
		if n >= 3 {
			code = http.StatusOK
		}
		return &http.Response{StatusCode: code, Body: http.NoBody, Header: http.Header{}}, nil
	})
	client := newTestClient(base, 3)

	resp, err := client.Get("http://example.test/x")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("made %d calls, want 3 (2 failures + 1 success)", got)
	}
}

func TestGivesUpAfterMaxRetries(t *testing.T) {
	var calls atomic.Int64
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusBadGateway, Body: http.NoBody, Header: http.Header{}}, nil
	})
	client := newTestClient(base, 2)

	resp, err := client.Get("http://example.test/x")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (final attempt returned)", resp.StatusCode)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("made %d calls, want 3 (1 + 2 retries)", got)
	}
}

func TestDoesNotRetrySuccess(t *testing.T) {
	var calls atomic.Int64
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: http.Header{}}, nil
	})
	client := newTestClient(base, 3)
	if _, err := client.Get("http://example.test/x"); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("made %d calls, want 1 (no retry on success)", got)
	}
}

func TestDoesNotRetryNonIdempotent(t *testing.T) {
	var calls atomic.Int64
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: http.NoBody, Header: http.Header{}}, nil
	})
	client := newTestClient(base, 3)

	// POST with no rewindable body must not be replayed.
	req, _ := http.NewRequest(http.MethodPost, "http://example.test/x", nil)
	if _, err := client.Do(req); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("made %d calls, want 1 (POST is not replayed)", got)
	}
}

func TestRetryStopsOnContextCancel(t *testing.T) {
	var calls atomic.Int64
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: http.NoBody, Header: http.Header{}}, nil
	})
	client := New(WithTransport(base), WithRetry(5, 10*time.Millisecond, 50*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: the first backoff must abort
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.test/x", nil)
	_, err := client.Do(req)
	if err == nil {
		t.Fatal("expected an error from a cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestRetryRewindsBody(t *testing.T) {
	// Each attempt must see the full request body, not the drained leftovers
	// of the previous attempt.
	var bodies []string
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("reading attempt body: %v", err)
		}
		r.Body.Close()
		bodies = append(bodies, string(b))
		code := http.StatusServiceUnavailable
		if len(bodies) >= 2 {
			code = http.StatusOK
		}
		return &http.Response{StatusCode: code, Body: http.NoBody, Header: http.Header{}}, nil
	})
	client := newTestClient(base, 3)

	// A GET with a body is unusual but legal, and it is the rewindable case
	// replayable() advertises: http.NewRequest sets GetBody for a bytes.Reader.
	req, err := http.NewRequest(http.MethodGet, "http://example.test/x", bytes.NewReader([]byte("payload")))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if len(bodies) != 2 {
		t.Fatalf("made %d attempts, want 2", len(bodies))
	}
	for i, b := range bodies {
		if b != "payload" {
			t.Errorf("attempt %d body = %q, want %q (body not rewound)", i+1, b, "payload")
		}
	}
}

func TestRetryAfterBeyondBudgetGivesUp(t *testing.T) {
	// A server Retry-After longer than maxDelay means "come back much later";
	// the client must surface the response instead of retrying early.
	var calls atomic.Int64
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Body:       http.NoBody,
			Header:     http.Header{"Retry-After": []string{"120"}},
		}, nil
	})
	client := newTestClient(base, 3) // maxDelay is 1ms in the test client

	resp, err := client.Get("http://example.test/x")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 surfaced to the caller", resp.StatusCode)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("made %d calls, want 1 (no early retry against Retry-After)", got)
	}
}

// timeoutError is a net.Error whose Timeout reports true.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

var _ net.Error = timeoutError{}

func TestRetryableErrorClassification(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"context canceled", context.Canceled, false},
		{"deadline exceeded", context.DeadlineExceeded, false},
		{"wrapped cancel", &net.OpError{Op: "dial", Err: context.Canceled}, false},
		{"eof", io.EOF, true},
		{"net timeout", timeoutError{}, true},
		{"connection refused", errors.New("connection refused"), true},
	}
	for _, tt := range tests {
		if got := retryableError(tt.err); got != tt.want {
			t.Errorf("retryableError(%s) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestRetryAfterHeaderParsed(t *testing.T) {
	resp := &http.Response{Header: http.Header{"Retry-After": []string{"2"}}}
	d, ok := retryAfter(resp)
	if !ok || d != 2*time.Second {
		t.Fatalf("retryAfter = (%v, %v), want (2s, true)", d, ok)
	}
	if _, ok := retryAfter(&http.Response{Header: http.Header{}}); ok {
		t.Error("retryAfter should be false when header absent")
	}
}

func TestEndToEndAgainstFlakyServer(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := New(WithRetry(3, time.Millisecond, 10*time.Millisecond))
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 after retry", resp.StatusCode)
	}
}

func TestNewTransportHardening(t *testing.T) {
	tr := NewTransport()
	if !tr.ForceAttemptHTTP2 {
		t.Error("expected HTTP/2 to be preferred")
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Error("expected a TLS 1.2 floor")
	}
	if tr.ResponseHeaderTimeout == 0 || tr.TLSHandshakeTimeout == 0 {
		t.Error("expected bounded response-header and TLS-handshake phases")
	}
}
