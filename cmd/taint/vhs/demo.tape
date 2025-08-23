###############################################
# taint CLI showcase
# - Pastel adaptive theming & semantic coloring
# - Multi-root analysis (xss)
# - Rich navigation: pkgs, cg, nodes, root
# - Call path discovery: exact, fuzzy, glob, regex
# - Taint checking across packages
# - Screen clearing + autocomplete exit
###############################################
Output ./vhs/demo.gif

Set Margin 20
Set MarginFill "#ffffff"
Set BorderRadius 10

Set FontSize 20
Set Width 1200
Set Height 640

# Launch interactive shell
Type "taint"
Sleep 400ms
Enter
Sleep 1500ms

# Load full example (HTTP handler + DB usage)
Type "load ./cmd/taint/example"
Sleep 300ms
Enter
Sleep 2600ms

# Show its callgraph
Type "cg"
Sleep 250ms
Enter
Sleep 2300ms

# Show nodes & current analysis root
Type "nodes"
Sleep 250ms
Enter
Sleep 1200ms

Type "root"
Sleep 250ms
Enter
Sleep 900ms

# Fuzzy search for handler business logic
Type "callpath fuzzy:business"
Sleep 250ms
Enter
Sleep 1400ms

# Taint check: request -> DB query (potential SQL injection path)
Type "check *net/http.Request (*database/sql.DB).Query"
Sleep 300ms
Enter
Sleep 2400ms

# Alternate source: URL.Query -> DB Query
Type "check (*net/url.URL).Query (*database/sql.DB).Query"
Sleep 300ms
Enter
Sleep 2400ms

# Demonstrate screen clear before exit
Type "clear"
Sleep 250ms
Enter
Sleep 800ms

# Exit via autocomplete (type prefix then Tab)
Type "ex"
Sleep 300ms
Tab
Sleep 300ms
Enter
Sleep 1000ms
