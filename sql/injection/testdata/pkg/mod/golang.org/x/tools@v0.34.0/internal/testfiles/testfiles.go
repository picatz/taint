// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package testfiles provides utilities for writing Go tests with files
// in testdata.
package testfiles

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/internal/testenv"
	"golang.org/x/tools/txtar"
)

// CopyToTmp copies the files and directories in src to a new temporary testing
// directory dst, and returns dst on success.
//
// After copying the files, it processes each of the 'old,new,' rename
// directives in order. Each rename directive moves the relative path "old"
// to the relative path "new" within the directory.
//
// Renaming allows tests to hide files whose names have
// special meaning, such as "go.mod" files or "testdata" directories
// from the go command, or ill-formed Go source files from gofmt.
//
// For example if we copy the directory testdata:
//
//	testdata/
//	    go.mod.test
//	    a/a.go
//	    b/b.go
//
// with the rename "go.mod.test,go.mod", the resulting files will be:
//
//	dst/
//	    go.mod
//	    a/a.go
//	    b/b.go
func CopyToTmp(t testing.TB, src fs.FS, rename ...string) string {
	dstdir := t.TempDir()

	if err := os.CopyFS(dstdir, src); err != nil {
		t.Fatal(err)
	}
	for _, r := range rename {
		old, new, found := strings.Cut(r, ",")
		if !found {
			t.Fatalf("rename directive %q does not contain delimiter %q", r, ",")
		}
		oldpath := filepath.Join(dstdir, old)
		newpath := filepath.Join(dstdir, new)
		if err := os.Rename(oldpath, newpath); err != nil {
			t.Fatal(err)
		}
	}

	return dstdir
}

// ExtractTxtarFileToTmp read a txtar archive on a given path,
// extracts it to a temporary directory, and returns the
// temporary directory.
func ExtractTxtarFileToTmp(t testing.TB, file string) string {
	ar, err := txtar.ParseFile(file)
	if err != nil {
		t.Fatal(err)
	}

	fs, err := txtar.FS(ar)
	if err != nil {
		t.Fatal(err)
	}
	return CopyToTmp(t, fs)
}

// LoadPackages loads typed syntax for all packages that match the
// patterns, interpreted relative to the archive root.
//
// The packages must be error-free.
func LoadPackages(t testing.TB, ar *txtar.Archive, patterns ...string) []*packages.Package {
	testenv.NeedsGoPackages(t)

	fs, err := txtar.FS(ar)
	if err != nil {
		t.Fatal(err)
	}
	dir := CopyToTmp(t, fs)

	cfg := &packages.Config{
		Mode: packages.NeedSyntax |
			packages.NeedTypesInfo |
			packages.NeedDeps |
			packages.NeedName |
			packages.NeedFiles |
			packages.NeedImports |
			packages.NeedCompiledGoFiles |
			packages.NeedTypes,
		Dir: dir,
		Env: append(os.Environ(),
			"GO111MODULES=on",
			"GOPATH=",
			"GOWORK=off",
			"GOPROXY=off"),
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		t.Fatal(err)
	}
	if num := packages.PrintErrors(pkgs); num > 0 {
		t.Fatalf("packages contained %d errors", num)
	}
	return pkgs
}
