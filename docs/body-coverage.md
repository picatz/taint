# Whole-program body coverage

`taint scan` connects selected packages through one call graph. It does not
build source bodies for every transitive dependency: `ssautil.Packages` builds
bodies only for initial packages matched by the supplied patterns. Imported
packages still have SSA declarations and may have modeled behavior. An
unmodeled helper whose body is omitted can interrupt a taint path.

Use `taint scan -coverage ./controllers ./object` to print a package-coverage
explanation to stderr. It lists imported, unselected dependencies belonging to
any selected package's exact module. Finding output (text, JSON, or SARIF),
exit status, roots, models, and source/sink matching are unchanged. The flag
adds no package loads or SSA builds. It traverses already loaded metadata and
sorts package IDs, using memory proportional to the number of dependencies.

Module identity includes module path, version, directory, go.mod file, and
replacement identity. A workspace's unselected sibling module is not treated
as the same module merely because both modules have `Main` set. Selecting
packages from multiple modules includes each of those module identities.
Package IDs preserve test variants. Missing module path or both directory and
go.mod metadata are treated conservatively as unknown; the diagnostic reports
when selected inputs cannot be classified. Other dependencies are counted,
not individually printed; these include third-party packages, standard-library
packages, and dependencies with unknown module identity.

This is a coverage diagnostic, not a completeness or recall guarantee.
Assembly/external declarations and synthetic functions may lack bodies even
in a selected package. A zero omitted-same-module count does not establish that
all dependencies have bodies or that all vulnerabilities can be found.

Explicitly selecting an additional package can expose its helper bodies, but
also changes the analysis input and potentially its library roots and matches.
Do not treat a result from wider patterns as an engine improvement on an
unchanged benchmark. There is deliberately no automatic dependency-body
expansion option: it needs a separate contract for roots and matching scope.
