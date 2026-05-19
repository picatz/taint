package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

// CacheDir is the on-disk root used to clone git targets. The default lives
// under .cache/taint-eval relative to the repo working directory; the
// TAINT_EVAL_CACHE environment variable overrides it.
type CacheDir string

// ResolveCacheDir picks a cache directory: explicit override > env var >
// default. The returned directory is created if it does not already exist.
func ResolveCacheDir(override string) (CacheDir, error) {
	dir := override
	if dir == "" {
		dir = os.Getenv("TAINT_EVAL_CACHE")
	}
	if dir == "" {
		dir = filepath.Join(".cache", "taint-eval")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolve cache dir: %w", err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return "", fmt.Errorf("create cache dir %s: %w", abs, err)
	}
	return CacheDir(abs), nil
}

// PathForGitTarget returns the on-disk directory used for a git target.
func (c CacheDir) PathForGitTarget(t Target) (string, error) {
	host, owner, name, err := splitRepoURL(t.Repo)
	if err != nil {
		return "", err
	}
	short := t.Commit
	if len(short) > 12 {
		short = short[:12]
	}
	return filepath.Join(string(c), host, owner, name+"@"+short), nil
}

// EnsureGitTarget makes sure the target is cloned at its pinned commit.
// Existing clones are detected and reused; mismatched commits or corrupt
// clones cause the directory to be wiped and re-cloned. Clone or network
// failures are returned as harness errors and should not be treated as
// analyzer findings.
func (c CacheDir) EnsureGitTarget(ctx context.Context, t Target) (string, error) {
	dest, err := c.PathForGitTarget(t)
	if err != nil {
		return "", err
	}
	if commitMatches(dest, t.Commit) {
		return dest, nil
	}
	// Wipe stale state before re-cloning. This is harness-owned scratch
	// space; do not delete anything outside the cache dir.
	if _, err := os.Stat(dest); err == nil {
		if !strings.HasPrefix(dest, string(c)) {
			return "", fmt.Errorf("refusing to remove path outside cache: %s", dest)
		}
		if err := os.RemoveAll(dest); err != nil {
			return "", fmt.Errorf("clean cache for %s: %w", t.Name, err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", err
	}
	repo, err := git.PlainCloneContext(ctx, dest, false, &git.CloneOptions{
		URL:  t.Repo,
		Tags: git.NoTags,
	})
	if err != nil {
		return "", fmt.Errorf("clone %s: %w", t.Repo, err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("worktree for %s: %w", t.Repo, err)
	}
	if err := wt.Checkout(&git.CheckoutOptions{Hash: plumbing.NewHash(t.Commit)}); err != nil {
		return "", fmt.Errorf("checkout %s@%s: %w", t.Repo, t.Commit, err)
	}
	return dest, nil
}

// commitMatches returns true when dir is a git checkout at the given commit.
func commitMatches(dir, commit string) bool {
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		return false
	}
	repo, err := git.PlainOpen(dir)
	if err != nil {
		return false
	}
	head, err := repo.Head()
	if err != nil {
		return false
	}
	return head.Hash().String() == commit
}

// splitRepoURL decomposes an https://host/owner/name(.git)? URL.
func splitRepoURL(raw string) (host, owner, name string, err error) {
	u, perr := url.Parse(raw)
	if perr != nil {
		return "", "", "", fmt.Errorf("parse repo url %s: %w", raw, perr)
	}
	if u.Host == "" {
		return "", "", "", fmt.Errorf("repo url %s missing host", raw)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("repo url %s missing owner/name", raw)
	}
	host = u.Host
	owner = parts[0]
	name = strings.TrimSuffix(parts[1], ".git")
	return host, owner, name, nil
}
