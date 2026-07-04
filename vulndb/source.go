package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// DefaultBaseURL is the canonical Go vulnerability database endpoint.
const DefaultBaseURL = "https://vuln.go.dev"

// ModuleIndexEntry is one module's row in the database's module index
// (index/modules.json): the module path and the advisories that touch it, each
// with the latest version that fixes it. The index is a cheap prefilter: a
// scanner fetches full advisories only for modules it actually depends on.
type ModuleIndexEntry struct {
	Path  string            `json:"path"`
	Vulns []ModuleIndexVuln `json:"vulns"`
}

// ModuleIndexVuln is one advisory reference within a module index entry.
type ModuleIndexVuln struct {
	ID       string    `json:"id"`
	Modified time.Time `json:"modified,omitzero"`
	Fixed    string    `json:"fixed,omitempty"`
}

// Source retrieves raw advisory data from a database. Implementations cover the
// HTTP endpoint at vuln.go.dev and a local mirror on any fs.FS. The scanner and
// the higher-level Client depend only on this interface, so an offline CI run,
// a test with a fixture filesystem, and a live scan share one code path.
type Source interface {
	// ModuleIndex returns the module index: every module with a known
	// advisory, for prefiltering.
	ModuleIndex(ctx context.Context) ([]ModuleIndexEntry, error)
	// Entry returns a single advisory by ID.
	Entry(ctx context.Context, id string) (*Entry, error)
}

// httpSource reads the database over HTTP from a base URL following the Go
// vulnerability database protocol (https://go.dev/security/vuln/database):
// index/modules.json and ID/<id>.json, each also available gzip-compressed.
type httpSource struct {
	base   *url.URL
	client *http.Client
}

// NewHTTPSource returns a Source that reads the database at baseURL (use
// DefaultBaseURL for the canonical endpoint) over the given HTTP client. A nil
// client uses http.DefaultClient.
func NewHTTPSource(baseURL string, client *http.Client) (Source, error) {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("vulndb: invalid base URL %q: %w", baseURL, err)
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &httpSource{base: u, client: client}, nil
}

func (s *httpSource) ModuleIndex(ctx context.Context) ([]ModuleIndexEntry, error) {
	var index []ModuleIndexEntry
	if err := s.getJSON(ctx, "index/modules.json", &index); err != nil {
		return nil, err
	}
	return index, nil
}

func (s *httpSource) Entry(ctx context.Context, id string) (*Entry, error) {
	if err := validID(id); err != nil {
		return nil, err
	}
	var e Entry
	if err := s.getJSON(ctx, "ID/"+id+".json", &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// getJSON fetches and decodes a database endpoint relative to the base URL.
func (s *httpSource) getJSON(ctx context.Context, endpoint string, dst any) error {
	full := *s.base
	full.Path = path.Join(s.base.Path, endpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full.String(), nil)
	if err != nil {
		return fmt.Errorf("vulndb: %w", err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("vulndb: fetching %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vulndb: fetching %s: unexpected status %s", endpoint, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return fmt.Errorf("vulndb: decoding %s: %w", endpoint, err)
	}
	return nil
}

// fsSource reads the database from a filesystem laid out like the HTTP
// endpoints: index/modules.json and ID/<id>.json. It backs both local mirrors
// (os.DirFS over an unpacked vulndb.zip) and tests (fstest.MapFS).
type fsSource struct {
	fsys fs.FS
}

// NewFSSource returns a Source reading the database from fsys, which must be
// laid out with index/modules.json and ID/<id>.json files, matching an
// unpacked vulndb.zip or the HTTP endpoint tree.
func NewFSSource(fsys fs.FS) Source {
	return &fsSource{fsys: fsys}
}

func (s *fsSource) ModuleIndex(ctx context.Context) ([]ModuleIndexEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var index []ModuleIndexEntry
	if err := s.readJSON("index/modules.json", &index); err != nil {
		return nil, err
	}
	return index, nil
}

func (s *fsSource) Entry(ctx context.Context, id string) (*Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validID(id); err != nil {
		return nil, err
	}
	var e Entry
	if err := s.readJSON("ID/"+id+".json", &e); err != nil {
		return nil, err
	}
	return &e, nil
}

func (s *fsSource) readJSON(name string, dst any) error {
	f, err := s.fsys.Open(name)
	if err != nil {
		return fmt.Errorf("vulndb: opening %s: %w", name, err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("vulndb: reading %s: %w", name, err)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("vulndb: decoding %s: %w", name, err)
	}
	return nil
}

// validID rejects advisory identifiers that are not well-formed, both as input
// validation and to prevent a crafted ID from escaping the endpoint path.
func validID(id string) error {
	if id == "" {
		return fmt.Errorf("vulndb: empty advisory ID")
	}
	if strings.ContainsAny(id, "/\\.") || strings.Contains(id, "..") {
		return fmt.Errorf("vulndb: invalid advisory ID %q", id)
	}
	return nil
}
