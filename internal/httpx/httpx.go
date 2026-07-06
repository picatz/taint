// Package httpx provides the module's hardened default HTTP client: a tuned,
// HTTP/2-capable transport with sane timeouts and connection pooling, wrapped
// in automatic retry-with-backoff for idempotent requests. It is internal on
// purpose. Callers get a standard *http.Client, so it drops into any API that
// takes one, and the behavior is composed from small functional options rather
// than a bespoke client type.
//
// The design goals, in order: never hang (every phase is bounded), be safe by
// default (TLS 1.2 floor, no silent downgrades), be polite and resilient to
// transient failures (bounded exponential backoff with full jitter, honoring
// Retry-After), and reuse connections efficiently across many small requests.
package httpx

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"time"
)

// Defaults tuned for many small JSON requests to a single host (the shape of a
// vulnerability-database scan). They bound every phase of a request so a stalled
// peer cannot wedge a caller.
const (
	defaultTimeout               = 30 * time.Second
	defaultDialTimeout           = 10 * time.Second
	defaultKeepAlive             = 30 * time.Second
	defaultTLSHandshakeTimeout   = 10 * time.Second
	defaultResponseHeaderTimeout = 20 * time.Second
	defaultExpectContinueTimeout = 1 * time.Second
	defaultIdleConnTimeout       = 90 * time.Second
	defaultMaxIdleConns          = 100
	defaultMaxIdleConnsPerHost   = 16

	defaultMaxRetries = 3
	defaultBaseDelay  = 200 * time.Millisecond
	defaultMaxDelay   = 5 * time.Second
)

// config is the resolved client configuration.
type config struct {
	timeout             time.Duration
	transport           http.RoundTripper
	maxRetries          int
	baseDelay, maxDelay time.Duration
}

// Option customizes a client built by New.
type Option func(*config)

// WithTimeout sets the overall per-request timeout (http.Client.Timeout),
// covering connect, redirects, and reading the body. Per-call context deadlines
// still apply and take precedence when shorter. Zero disables the client-level
// timeout, leaving only the transport-phase timeouts and any context deadline.
func WithTimeout(d time.Duration) Option {
	return func(c *config) { c.timeout = d }
}

// WithTransport replaces the base transport (before retry wrapping). Use it to
// inject a test RoundTripper or a preconfigured proxy transport. A nil
// transport is ignored.
func WithTransport(rt http.RoundTripper) Option {
	return func(c *config) {
		if rt != nil {
			c.transport = rt
		}
	}
}

// WithRetry sets the maximum number of retries and the backoff bounds for
// idempotent requests. maxRetries of 0 disables retrying.
//
// Note the client-level timeout (WithTimeout) spans all attempts and the
// backoff between them; when raising maxRetries or the delays, raise the
// overall timeout to match or later attempts will have little budget left.
func WithRetry(maxRetries int, baseDelay, maxDelay time.Duration) Option {
	return func(c *config) {
		c.maxRetries = maxRetries
		if baseDelay > 0 {
			c.baseDelay = baseDelay
		}
		if maxDelay > 0 {
			c.maxDelay = maxDelay
		}
	}
}

// New returns a standard *http.Client with a hardened transport and retry
// behavior, customized by opts. The returned client is safe for concurrent use
// and reuses connections across requests; construct one and share it.
func New(opts ...Option) *http.Client {
	cfg := config{
		timeout:    defaultTimeout,
		transport:  NewTransport(),
		maxRetries: defaultMaxRetries,
		baseDelay:  defaultBaseDelay,
		maxDelay:   defaultMaxDelay,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	rt := cfg.transport
	if cfg.maxRetries > 0 {
		rt = &retryTransport{
			base:       rt,
			maxRetries: cfg.maxRetries,
			baseDelay:  cfg.baseDelay,
			maxDelay:   cfg.maxDelay,
			sleep:      sleepContext,
		}
	}
	return &http.Client{
		Timeout:   cfg.timeout,
		Transport: rt,
	}
}

// NewTransport returns the hardened base transport: bounded dial, TLS, and
// response-header phases, HTTP/2 preferred, a TLS 1.2 floor, and a connection
// pool sized for repeated requests to a small number of hosts. It is exported
// so callers who need their own retry or middleware stack can build on it.
func NewTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   defaultDialTimeout,
			KeepAlive: defaultKeepAlive,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          defaultMaxIdleConns,
		MaxIdleConnsPerHost:   defaultMaxIdleConnsPerHost,
		IdleConnTimeout:       defaultIdleConnTimeout,
		TLSHandshakeTimeout:   defaultTLSHandshakeTimeout,
		ResponseHeaderTimeout: defaultResponseHeaderTimeout,
		ExpectContinueTimeout: defaultExpectContinueTimeout,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
}

// retryTransport retries idempotent requests that fail transiently, with
// exponential backoff and full jitter, honoring a server Retry-After. It only
// retries requests it can safely replay (an idempotent method and a rewindable
// body), and it always drains and closes a discarded response body so the
// underlying connection can be reused.
type retryTransport struct {
	base       http.RoundTripper
	maxRetries int
	baseDelay  time.Duration
	maxDelay   time.Duration
	// sleep waits for d or until the request context is done; overridable in
	// tests. It returns the context error when the context ends first.
	sleep func(*http.Request, time.Duration) error
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	attempts := t.maxRetries + 1
	var resp *http.Response
	var err error
	for attempt := range attempts {
		resp, err = t.base.RoundTrip(req)

		if !t.shouldRetry(req, resp, err) || attempt == attempts-1 {
			return resp, err
		}

		delay, ok := t.backoff(attempt, resp)
		if !ok {
			// The server asked us to wait longer than the backoff budget
			// allows; hammering it sooner would be impolite, so surface the
			// response and let the caller decide.
			return resp, err
		}

		// Rebuild the next attempt before discarding this response, so a
		// failed rebuild can still surface the outcome we already have.
		next, rerr := nextAttempt(req)
		if rerr != nil {
			return resp, err
		}

		// Discard the failed response so its connection is reused.
		drain(resp)
		if serr := t.sleep(req, delay); serr != nil {
			// The rebuilt attempt will never be sent; close the fresh body
			// opened for it (a custom GetBody may hold a file open).
			if next != req && next.Body != nil {
				_ = next.Body.Close()
			}
			return nil, serr
		}
		req = next
	}
	return resp, err
}

// nextAttempt returns the request to send on the next attempt. A bodyless
// request is reused as-is. A request with a body is cloned with a fresh body
// from GetBody: the previous attempt consumed (and the transport closed) the
// old one, so replaying the same Request would send an empty body.
func nextAttempt(req *http.Request) (*http.Request, error) {
	if req.Body == nil || req.Body == http.NoBody || req.GetBody == nil {
		return req, nil
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	clone := req.Clone(req.Context())
	clone.Body = body
	return clone, nil
}

// shouldRetry reports whether a failed attempt is worth replaying: a transient
// transport error, or a retryable status (429, 503, and the other 5xx), on a
// request that is safe to replay.
func (t *retryTransport) shouldRetry(req *http.Request, resp *http.Response, err error) bool {
	if !replayable(req) {
		return false
	}
	if err != nil {
		return retryableError(err)
	}
	switch resp.StatusCode {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

// backoff returns the delay before the next attempt: a server Retry-After when
// present and sane, otherwise exponential backoff with full jitter capped at
// maxDelay. It reports false when the server asked for a wait beyond maxDelay,
// meaning the attempt should not be retried at all rather than retried early.
func (t *retryTransport) backoff(attempt int, resp *http.Response) (time.Duration, bool) {
	if ra, ok := retryAfter(resp); ok {
		if ra > t.maxDelay {
			return 0, false
		}
		return ra, true
	}
	// Exponential: base * 2^attempt, capped, then full jitter in [0, cap].
	// Compare in float space before converting: a float64 beyond the int64
	// range converts to an implementation-defined Duration per the Go spec.
	backoff := float64(t.baseDelay) * math.Ldexp(1, attempt)
	capped := t.maxDelay
	if backoff < float64(t.maxDelay) {
		capped = time.Duration(backoff)
	}
	if capped <= 0 {
		return 0, true
	}
	return time.Duration(rand.Int64N(int64(capped))), true
}

// replayable reports whether a request can be safely retried: an idempotent
// method and a body that can be rewound (nil, or with GetBody set).
func replayable(req *http.Request) bool {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
	default:
		return false
	}
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		return false
	}
	return true
}

// retryableError reports whether a transport error is transient. Context
// cancellation and deadline are not retryable; timeouts and temporary network
// errors are.
func retryableError(err error) bool {
	// A dead context can never succeed on retry, and checking it here keeps
	// the transport's descriptive error instead of a bare ctx.Err() from the
	// sleep between attempts. Note net.Error's Timeout is true for
	// context.DeadlineExceeded, so this must come first.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, io.EOF) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	// A generic transport error (connection refused/reset) is worth one retry.
	return true
}

// retryAfter parses a Retry-After header (delta-seconds or an HTTP date) into a
// delay, returning false when absent or unparseable.
func retryAfter(resp *http.Response) (time.Duration, bool) {
	if resp == nil {
		return 0, false
	}
	v := resp.Header.Get("Retry-After")
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if when, err := http.ParseTime(v); err == nil {
		if d := time.Until(when); d > 0 {
			return d, true
		}
		return 0, true
	}
	return 0, false
}

// drain reads and closes a response body so its connection returns to the pool.
func drain(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	_ = resp.Body.Close()
}

// sleepContext waits for d or until the request context is done, returning the
// context error if the context ends first.
func sleepContext(req *http.Request, d time.Duration) error {
	if d <= 0 {
		return req.Context().Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-req.Context().Done():
		return req.Context().Err()
	case <-timer.C:
		return nil
	}
}
