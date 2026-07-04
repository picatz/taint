package vulndb

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// cachedSource wraps an upstream Source with a two-level cache: a process-wide
// in-memory map so one scan never fetches the same advisory twice, and an
// optional on-disk store so repeated runs (a CI job, an editor save loop) reuse
// prior downloads. Advisories are content-addressed by ID and change rarely, so
// the on-disk copy is served whenever it is younger than the configured TTL.
type cachedSource struct {
	upstream Source
	dir      string
	ttl      time.Duration

	mu       sync.Mutex
	memIdx   []ModuleIndexEntry
	memIdxOK bool
	memEntry map[string]*Entry
}

// CacheConfig configures an on-disk advisory cache.
type CacheConfig struct {
	// Dir is the cache directory. Empty uses os.UserCacheDir()/taint/vulndb.
	Dir string
	// TTL is how long a cached file is served before refetching. Zero uses a
	// default of one hour, which keeps a scan fast while staying close to the
	// upstream database.
	TTL time.Duration
}

// NewCachedSource wraps upstream with the cache described by cfg. When the
// on-disk directory cannot be prepared the cache degrades to in-memory only, so
// a read-only environment still benefits from per-run memoization.
func NewCachedSource(upstream Source, cfg CacheConfig) Source {
	dir := cfg.Dir
	if dir == "" {
		if base, err := os.UserCacheDir(); err == nil {
			dir = filepath.Join(base, "taint", "vulndb")
		}
	}
	if dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			dir = "" // fall back to memory-only
		}
	}
	ttl := cfg.TTL
	if ttl == 0 {
		ttl = time.Hour
	}
	return &cachedSource{
		upstream: upstream,
		dir:      dir,
		ttl:      ttl,
		memEntry: make(map[string]*Entry),
	}
}

func (c *cachedSource) ModuleIndex(ctx context.Context) ([]ModuleIndexEntry, error) {
	c.mu.Lock()
	if c.memIdxOK {
		idx := c.memIdx
		c.mu.Unlock()
		return idx, nil
	}
	c.mu.Unlock()

	// The module index changes with every database update, so it is cached with
	// the TTL rather than treated as immutable.
	path := c.diskPath("index", "modules.json")
	if data, ok := c.readFresh(path); ok {
		var idx []ModuleIndexEntry
		if err := json.Unmarshal(data, &idx); err == nil {
			c.storeIndex(idx)
			return idx, nil
		}
	}

	idx, err := c.upstream.ModuleIndex(ctx)
	if err != nil {
		return nil, err
	}
	c.writeDisk(path, idx)
	c.storeIndex(idx)
	return idx, nil
}

func (c *cachedSource) Entry(ctx context.Context, id string) (*Entry, error) {
	if err := validID(id); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if e, ok := c.memEntry[id]; ok {
		c.mu.Unlock()
		return e, nil
	}
	c.mu.Unlock()

	path := c.diskPath("ID", id+".json")
	if data, ok := c.readFresh(path); ok {
		var e Entry
		if err := json.Unmarshal(data, &e); err == nil {
			c.storeEntry(id, &e)
			return &e, nil
		}
	}

	e, err := c.upstream.Entry(ctx, id)
	if err != nil {
		return nil, err
	}
	c.writeDisk(path, e)
	c.storeEntry(id, e)
	return e, nil
}

func (c *cachedSource) storeIndex(idx []ModuleIndexEntry) {
	c.mu.Lock()
	c.memIdx, c.memIdxOK = idx, true
	c.mu.Unlock()
}

func (c *cachedSource) storeEntry(id string, e *Entry) {
	c.mu.Lock()
	c.memEntry[id] = e
	c.mu.Unlock()
}

func (c *cachedSource) diskPath(parts ...string) string {
	if c.dir == "" {
		return ""
	}
	return filepath.Join(append([]string{c.dir}, parts...)...)
}

// readFresh returns the file's contents when it exists and is younger than the
// TTL.
func (c *cachedSource) readFresh(path string) ([]byte, bool) {
	if path == "" {
		return nil, false
	}
	info, err := os.Stat(path)
	if err != nil || time.Since(info.ModTime()) > c.ttl {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return data, true
}

// writeDisk stores v as JSON at path, best-effort: a cache write failure never
// fails the scan.
func (c *cachedSource) writeDisk(path string, v any) {
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}
