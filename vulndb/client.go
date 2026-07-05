package vulndb

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/sync/errgroup"
)

// maxConcurrentFetches bounds how many advisory files are fetched at once,
// matching govulncheck's client. It keeps a scan polite to the database and
// bounds memory without meaningfully slowing a real dependency set.
const maxConcurrentFetches = 10

// Client is a high-level view over a Source: it resolves modules to the
// advisories that affect them and hydrates full advisory records, hiding the
// index-then-fetch protocol behind a single call. It is safe for concurrent
// use if its Source is.
type Client struct {
	src Source
}

// NewClient returns a Client backed by src.
func NewClient(src Source) *Client {
	return &Client{src: src}
}

// Module is a module at a resolved version, the unit a scan queries against.
type Module struct {
	// Path is the module path, StdlibModule, or ToolchainModule.
	Path string
	// Version is the resolved version (any of the accepted spellings; the
	// standard library and toolchain accept "go1.21.3"). An empty version
	// means "match any", conservatively keeping every advisory for the module.
	Version string
}

// AffectingEntries returns the advisories that affect any of the given modules
// at their versions, sorted by ID. Withdrawn advisories are excluded. Only
// modules present in the database's module index are queried, so an
// application with no known-vulnerable dependencies fetches nothing beyond the
// index.
func (c *Client) AffectingEntries(ctx context.Context, modules []Module) ([]*Entry, error) {
	index, err := c.src.ModuleIndex(ctx)
	if err != nil {
		return nil, err
	}
	indexByPath := make(map[string][]ModuleIndexVuln, len(index))
	for _, m := range index {
		indexByPath[m.Path] = m.Vulns
	}

	// Collect the candidate advisory IDs for the modules we actually have,
	// deduplicating across modules that share an advisory.
	candidateIDs := make(map[string]struct{})
	for _, m := range modules {
		for _, v := range indexByPath[m.Path] {
			candidateIDs[v.ID] = struct{}{}
		}
	}
	if len(candidateIDs) == 0 {
		return nil, nil
	}

	entries, err := c.fetchEntries(ctx, candidateIDs)
	if err != nil {
		return nil, err
	}

	// Keep only advisories that actually affect one of the requested module
	// versions, and that are not withdrawn. The index is a coarse prefilter
	// (module-level); this is the exact version check.
	versionByPath := make(map[string]string, len(modules))
	for _, m := range modules {
		versionByPath[m.Path] = m.Version
	}
	var affecting []*Entry
	for _, e := range entries {
		if e.IsWithdrawn() {
			continue
		}
		if entryAffectsAny(e, versionByPath) {
			affecting = append(affecting, e)
		}
	}
	slices.SortFunc(affecting, func(a, b *Entry) int { return strings.Compare(a.ID, b.ID) })
	return affecting, nil
}

// entryAffectsAny reports whether e affects any requested module at its
// resolved version.
func entryAffectsAny(e *Entry, versionByPath map[string]string) bool {
	for _, a := range e.Affected {
		version, ok := versionByPath[a.ModulePath()]
		if !ok {
			continue
		}
		if a.AffectsVersion(version) {
			return true
		}
	}
	return false
}

// fetchEntries hydrates the given advisory IDs concurrently, bounded by
// maxConcurrentFetches. The returned slice order is unspecified; callers sort.
func (c *Client) fetchEntries(ctx context.Context, ids map[string]struct{}) ([]*Entry, error) {
	idList := make([]string, 0, len(ids))
	for id := range ids {
		idList = append(idList, id)
	}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentFetches)
	entries := make([]*Entry, len(idList))
	for i, id := range idList {
		g.Go(func() error {
			e, err := c.src.Entry(ctx, id)
			if err != nil {
				return fmt.Errorf("vulndb: fetching %s: %w", id, err)
			}
			entries[i] = e
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return entries, nil
}
