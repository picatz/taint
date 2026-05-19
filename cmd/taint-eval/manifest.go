package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// Manifest describes the set of evaluation targets to run analyzers against.
type Manifest struct {
	Targets []Target `yaml:"targets"`
}

// TargetKind distinguishes locally fixed source trees from cloned git
// repositories pinned to a commit.
type TargetKind string

const (
	KindLocal TargetKind = "local"
	KindGit   TargetKind = "git"
)

// Target describes a single repository or fixture to evaluate.
type Target struct {
	Name      string     `yaml:"name"`
	Kind      TargetKind `yaml:"kind"`
	Path      string     `yaml:"path,omitempty"`
	Repo      string     `yaml:"repo,omitempty"`
	Commit    string     `yaml:"commit,omitempty"`
	Packages  []string   `yaml:"packages,omitempty"`
	Analyzers []string   `yaml:"analyzers"`
}

// LoadManifest reads a YAML manifest from path and validates it.
// The returned manifest's local paths are still relative to the manifest
// directory; callers should join with ManifestDir when resolving.
func LoadManifest(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest %s: %w", path, err)
	}
	var m Manifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse manifest %s: %w", path, err)
	}
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("manifest %s: %w", path, err)
	}
	return &m, nil
}

func (m *Manifest) validate() error {
	seen := make(map[string]struct{}, len(m.Targets))
	for i := range m.Targets {
		t := &m.Targets[i]
		if t.Name == "" {
			return fmt.Errorf("target %d: missing name", i)
		}
		if _, dup := seen[t.Name]; dup {
			return fmt.Errorf("duplicate target name %q", t.Name)
		}
		seen[t.Name] = struct{}{}
		switch t.Kind {
		case KindLocal:
			if t.Path == "" {
				return fmt.Errorf("target %q: local target requires path", t.Name)
			}
		case KindGit:
			if t.Repo == "" {
				return fmt.Errorf("target %q: git target requires repo", t.Name)
			}
			if t.Commit == "" {
				return fmt.Errorf("target %q: git target requires pinned commit", t.Name)
			}
		default:
			return fmt.Errorf("target %q: unknown kind %q", t.Name, t.Kind)
		}
		if len(t.Analyzers) == 0 {
			return fmt.Errorf("target %q: no analyzers configured", t.Name)
		}
		if len(t.Packages) == 0 {
			t.Packages = []string{"./..."}
		}
		sort.Strings(t.Analyzers)
	}
	return nil
}

// FindTarget returns the target with the given name, or nil if it does not
// exist in the manifest.
func (m *Manifest) FindTarget(name string) *Target {
	for i := range m.Targets {
		if m.Targets[i].Name == name {
			return &m.Targets[i]
		}
	}
	return nil
}

// SelectTargets returns the targets in the manifest matching the selector.
// Special selectors:
//
//	""       — all targets
//	"local"  — local targets only (no clone)
//	"git"    — git targets only
//
// Anything else is treated as a single target name.
func (m *Manifest) SelectTargets(selector string) ([]Target, error) {
	switch selector {
	case "":
		return append([]Target(nil), m.Targets...), nil
	case string(KindLocal):
		return m.filterKind(KindLocal), nil
	case string(KindGit):
		return m.filterKind(KindGit), nil
	}
	if t := m.FindTarget(selector); t != nil {
		return []Target{*t}, nil
	}
	return nil, fmt.Errorf("unknown target selector %q", selector)
}

func (m *Manifest) filterKind(kind TargetKind) []Target {
	out := make([]Target, 0, len(m.Targets))
	for _, t := range m.Targets {
		if t.Kind == kind {
			out = append(out, t)
		}
	}
	return out
}

// ResolveLocalPath joins a manifest-relative local path with the manifest
// directory, returning an absolute path.
func ResolveLocalPath(manifestDir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Clean(filepath.Join(manifestDir, p))
}
