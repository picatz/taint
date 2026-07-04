package httpx

import (
	"context"
	"crypto/tls"
	"errors"
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
