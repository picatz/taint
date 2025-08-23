package callgraphutil

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"golang.org/x/tools/go/callgraph"
)

// MatchStrategy represents different ways to match function names
type MatchStrategy int

const (
	// MatchExact requires an exact string match (default)
	MatchExact MatchStrategy = iota
	// MatchFuzzy uses substring matching
	MatchFuzzy
	// MatchGlob uses shell-style pattern matching with *, ?, []
	MatchGlob
	// MatchRegex uses regular expression matching
	MatchRegex
)

// String returns a human-readable description of the match strategy
func (m MatchStrategy) String() string {
	switch m {
	case MatchExact:
		return "exact"
	case MatchFuzzy:
		return "fuzzy"
	case MatchGlob:
		return "glob"
	case MatchRegex:
		return "regex"
	default:
		return "unknown"
	}
}

// ParseMatchStrategy parses a strategy string into a MatchStrategy
func ParseMatchStrategy(strategy string) MatchStrategy {
	switch strings.ToLower(strategy) {
	case "fuzzy", "fuzz", "substring", "contains":
		return MatchFuzzy
	case "glob", "pattern":
		return MatchGlob
	case "regex", "regexp", "re":
		return MatchRegex
	default:
		return MatchExact
	}
}

// FunctionMatcher provides flexible function name matching with multiple strategies
type FunctionMatcher struct {
	pattern  string
	strategy MatchStrategy
	regex    *regexp.Regexp // compiled regex for MatchRegex strategy
}

// NewFunctionMatcher creates a new matcher with explicit strategy
func NewFunctionMatcher(pattern string, strategy MatchStrategy) (*FunctionMatcher, error) {
	matcher := &FunctionMatcher{
		pattern:  pattern,
		strategy: strategy,
	}

	// Pre-compile regex if needed
	if strategy == MatchRegex {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern '%s': %w", pattern, err)
		}
		matcher.regex = regex
	}

	return matcher, nil
}

// NewFunctionMatcherFromString creates a matcher by parsing a pattern with optional prefix
// Supported formats:
//   - "exact:pattern" - exact matching
//   - "fuzzy:pattern" - substring matching
//   - "glob:pattern" - glob pattern matching
//   - "regex:pattern" - regular expression matching
//   - "pattern" - defaults to exact matching
func NewFunctionMatcherFromString(input string) (*FunctionMatcher, error) {
	var strategy MatchStrategy
	var pattern string

	// Check for explicit strategy prefixes
	if strings.Contains(input, ":") {
		parts := strings.SplitN(input, ":", 2)
		if len(parts) == 2 {
			strategyStr := strings.ToLower(parts[0])
			pattern = parts[1]

			switch strategyStr {
			case "exact":
				strategy = MatchExact
			case "fuzzy", "fuzz", "substring":
				strategy = MatchFuzzy
			case "glob", "pattern":
				strategy = MatchGlob
			case "regex", "regexp", "re":
				strategy = MatchRegex
			default:
				// Not a recognized strategy prefix, treat entire string as exact pattern
				strategy = MatchExact
				pattern = input
			}
		} else {
			strategy = MatchExact
			pattern = input
		}
	} else {
		// No prefix, default to exact matching
		strategy = MatchExact
		pattern = input
	}

	return NewFunctionMatcher(pattern, strategy)
}

// Match returns true if the function name matches according to the strategy
func (m *FunctionMatcher) Match(funcName string) bool {
	switch m.strategy {
	case MatchExact:
		return funcName == m.pattern
	case MatchFuzzy:
		return strings.Contains(funcName, m.pattern)
	case MatchGlob:
		matched, err := path.Match(m.pattern, funcName)
		if err != nil {
			// Invalid glob pattern, fall back to exact match
			return funcName == m.pattern
		}
		return matched
	case MatchRegex:
		if m.regex == nil {
			return false
		}
		return m.regex.MatchString(funcName)
	default:
		return false
	}
}

// Strategy returns the matching strategy being used
func (m *FunctionMatcher) Strategy() MatchStrategy {
	return m.strategy
}

// Pattern returns the pattern being matched
func (m *FunctionMatcher) Pattern() string {
	return m.pattern
}

// String returns a string representation of the matcher
func (m *FunctionMatcher) String() string {
	return fmt.Sprintf("%s:%s", m.strategy.String(), m.pattern)
}

// PathsSearchCallToWithMatcher returns paths that call functions matching the given matcher
func PathsSearchCallToWithMatcher(start *callgraph.Node, matcher *FunctionMatcher) Paths {
	return PathsSearch(start, func(n *callgraph.Node) bool {
		if n == nil || n.Func == nil {
			return false
		}
		return matcher.Match(n.Func.String())
	})
}

// PathsSearchCallToAdvanced provides advanced function matching with automatic strategy detection.
// This is the standard function for finding paths from a single starting node to functions matching
// a pattern. The pattern format determines the matching strategy:
//   - "pattern" or "exact:pattern" → exact string matching
//   - "fuzzy:pattern" → substring/fuzzy matching
//   - "glob:pattern" → shell-style glob matching
//   - "regex:pattern" → regular expression matching
//
// Returns all discovered paths, the detected strategy, and any error that occurred.
func PathsSearchCallToAdvanced(start *callgraph.Node, pattern string) ([]Path, MatchStrategy, error) {
	matcher, err := NewFunctionMatcherFromString(pattern)
	if err != nil {
		return nil, MatchExact, err
	}

	paths := PathsSearchCallToWithMatcher(start, matcher)
	return []Path(paths), matcher.Strategy(), nil
}

// PathsSearchCallToAdvancedAllNodes provides comprehensive function matching across all nodes in a callgraph.
// Unlike PathsSearchCallToAdvanced, this function handles disconnected callgraphs by searching beyond
// just the nodes reachable from the root, making it ideal for library analysis where functions may not
// be directly connected to the main entry point.
//
// The function uses a two-phase approach:
//  1. First attempts normal path search from the callgraph root
//  2. If no paths found, scans all nodes for matches and finds direct callers
//
// Returns all discovered paths, the matching strategy used, and any error that occurred.
func PathsSearchCallToAdvancedAllNodes(graph *callgraph.Graph, pattern string) ([]Path, MatchStrategy, error) {
	matcher, err := NewFunctionMatcherFromString(pattern)
	if err != nil {
		return nil, MatchExact, err
	}

	var allPaths Paths

	// Phase 1: Try the standard search from root
	if graph.Root != nil {
		rootPaths := PathsSearchCallToWithMatcher(graph.Root, matcher)
		allPaths = append(allPaths, rootPaths...)
	}

	// Phase 2: Handle disconnected components by searching all nodes
	if len(allPaths) == 0 {
		for _, node := range graph.Nodes {
			if node == nil || node.Func == nil {
				continue
			}
			if matcher.Match(node.Func.String()) {
				// Look for any direct caller of this matching node
				pathFound := false
				for _, potentialCaller := range graph.Nodes {
					if potentialCaller == nil || potentialCaller == node {
						continue
					}
					for _, edge := range potentialCaller.Out {
						if edge.Callee == node {
							// Found a direct caller → callee relationship
							path := Path{edge}
							allPaths = append(allPaths, path)
							pathFound = true
							break
						}
					}
					if pathFound {
						break
					}
				}

				// If no caller found, it's a standalone matching node
				if !pathFound {
					allPaths = append(allPaths, Path{})
				}
			}
		}
	}

	return []Path(allPaths), matcher.Strategy(), nil
}

// PathsSearchCallToAdvancedWithStrategy provides advanced function matching with explicit strategy
func PathsSearchCallToAdvancedWithStrategy(start *callgraph.Node, pattern string, strategy MatchStrategy) (Paths, error) {
	matcher, err := NewFunctionMatcher(pattern, strategy)
	if err != nil {
		return nil, err
	}

	paths := PathsSearchCallToWithMatcher(start, matcher)
	return paths, nil
}
