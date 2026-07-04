package vulndb

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// countingSource wraps a Source and counts calls, to prove the cache elides
// upstream fetches.
type countingSource struct {
	inner      Source
	indexCalls atomic.Int64
	entryCalls atomic.Int64
}

func (c *countingSource) ModuleIndex(ctx context.Context) ([]ModuleIndexEntry, error) {
	c.indexCalls.Add(1)
	return c.inner.ModuleIndex(ctx)
}

func (c *countingSource) Entry(ctx context.Context, id string) (*Entry, error) {
	c.entryCalls.Add(1)
	return c.inner.Entry(ctx, id)
}

func TestCachedSourceMemoizes(t *testing.T) {
	base := fixtureDB(t, `[{"path":"m","vulns":[{"id":"GO-2020-0001"}]}]`, map[string]string{
		"GO-2020-0001": `{"id":"GO-2020-0001"}`,
	})
	counter := &countingSource{inner: base}
	cache := NewCachedSource(counter, CacheConfig{Dir: t.TempDir(), TTL: time.Hour})

	ctx := context.Background()
	for range 3 {
		if _, err := cache.ModuleIndex(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := cache.Entry(ctx, "GO-2020-0001"); err != nil {
			t.Fatal(err)
		}
	}
	if got := counter.indexCalls.Load(); got != 1 {
		t.Errorf("index fetched %d times, want 1 (cached)", got)
	}
	if got := counter.entryCalls.Load(); got != 1 {
		t.Errorf("entry fetched %d times, want 1 (cached)", got)
	}
}

func TestCachedSourceReusesDiskAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	base := fixtureDB(t, `[{"path":"m","vulns":[{"id":"GO-2020-0001"}]}]`, map[string]string{
		"GO-2020-0001": `{"id":"GO-2020-0001"}`,
	})
	counter := &countingSource{inner: base}

	ctx := context.Background()
	// First instance populates the on-disk cache.
	first := NewCachedSource(counter, CacheConfig{Dir: dir, TTL: time.Hour})
	if _, err := first.Entry(ctx, "GO-2020-0001"); err != nil {
		t.Fatal(err)
	}
	// A fresh instance (new process, cold memory) must serve from disk.
	second := NewCachedSource(counter, CacheConfig{Dir: dir, TTL: time.Hour})
	if _, err := second.Entry(ctx, "GO-2020-0001"); err != nil {
		t.Fatal(err)
	}
	if got := counter.entryCalls.Load(); got != 1 {
		t.Errorf("entry fetched %d times across instances, want 1 (disk cache)", got)
	}
}
