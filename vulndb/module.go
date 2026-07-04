package vulndb

import "strings"

// StdlibModule is the pseudo-module path the Go database uses for the standard
// library. A build reports standard-library packages with no module, so a
// scanner maps them to this name before querying.
const StdlibModule = stdlibModule

// ToolchainModule is the pseudo-module path the Go database uses for the Go
// toolchain (the cmd/... commands and the compiler).
const ToolchainModule = toolchainModule

// ModulePath returns the module an affected entry names: an import path for a
// third-party module, or the StdlibModule / ToolchainModule pseudo-module for
// standard-library and toolchain advisories.
func (a Affected) ModulePath() string {
	return a.Package.Name
}

// IsStdlib reports whether the affected entry is a standard-library advisory.
func (a Affected) IsStdlib() bool {
	return a.Package.Name == stdlibModule
}

// IsToolchain reports whether the affected entry is a toolchain advisory.
func (a Affected) IsToolchain() bool {
	return a.Package.Name == toolchainModule
}

// packageInModule reports whether importPath belongs to modulePath, i.e. it is
// the module itself or a subpackage of it. The standard library (StdlibModule)
// contains any import path that is not itself a module path, but that
// determination is the caller's; here stdlib matches any non-dotted first path
// segment only when modulePath is StdlibModule.
func packageInModule(importPath, modulePath string) bool {
	if modulePath == stdlibModule {
		return isStdlibPath(importPath)
	}
	if importPath == modulePath {
		return true
	}
	return strings.HasPrefix(importPath, modulePath+"/")
}

// isStdlibPath reports whether an import path is part of the standard library.
// Standard-library import paths have no dot in their first segment (they are
// not domain-qualified), which distinguishes them from module paths like
// "github.com/x/y". The "cmd/..." tree is the toolchain, not the library.
func isStdlibPath(importPath string) bool {
	if importPath == "" {
		return false
	}
	first, _, _ := strings.Cut(importPath, "/")
	if strings.Contains(first, ".") {
		return false
	}
	if first == "cmd" {
		return false
	}
	return true
}
