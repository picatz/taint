package callgraphutil

import (
	"bytes"

	"golang.org/x/tools/go/callgraph"
)

// Path is a sequence of callgraph.Edges, where each edge
// represents a call from a caller to a callee, making up
// a "chain" of calls, e.g.: main → foo → bar → baz.
type Path []*callgraph.Edge

// Empty returns true if the path is empty, false otherwise.
func (p Path) Empty() bool {
	return len(p) == 0
}

// First returns the first edge in the path, or nil if the path is empty.
func (p Path) First() *callgraph.Edge {
	if len(p) == 0 {
		return nil
	}
	return p[0]
}

// Last returns the last edge in the path, or nil if the path is empty.
func (p Path) Last() *callgraph.Edge {
	if len(p) == 0 {
		return nil
	}
	return p[len(p)-1]
}

// String returns a string representation of the path which
// is a sequence of edges separated by " → ".
//
// Intended to be used while debugging.
func (p Path) String() string {
	var buf bytes.Buffer
	for i, e := range p {
		if i == 0 {
			buf.WriteString(e.Caller.String())
		}

		buf.WriteString(" → ")

		buf.WriteString(e.Callee.String())
	}
	return buf.String()
}

// Paths is a collection of paths, which may be logically grouped
// together, e.g.: all paths from main to foo, or all paths from
// main to bar.
type Paths []Path

// Shortest returns the shortest path in the collection of paths.
//
// If there are no paths, this returns nil. If there are multiple
// paths of the same length, this returns the first path found.
func (p Paths) Shortest() Path {
	if len(p) == 0 {
		return nil
	}

	shortest := p[0]
	for _, path := range p {
		if len(path) < len(shortest) {
			shortest = path
		}
	}

	return shortest
}

// Longest returns the longest path in the collection of paths.
//
// If there are no paths, this returns nil. If there are multiple
// paths of the same length, the first path found is returned.
func (p Paths) Longest() Path {
	if len(p) == 0 {
		return nil
	}

	longest := p[0]
	for _, path := range p {
		if len(path) > len(longest) {
			longest = path
		}
	}

	return longest
}

// PathSearch returns the first path found from the start node
// to a node that matches the isMatch function. This is a depth
// first search, so it will return the first path found, which
// may not be the shortest path.
//
// To find all paths, use PathsSearch, which returns a collection
// of paths.
func PathSearch(start *callgraph.Node, isMatch func(*callgraph.Node) bool) Path {
	var (
		stack = make(Path, 0, 32)
		seen  = make(map[*callgraph.Node]bool)

		search func(n *callgraph.Node) Path
	)

	search = func(n *callgraph.Node) Path {
		if !seen[n] {
			// debug("searching: %v\n", n)
			seen[n] = true
			if isMatch(n) {
				return stack
			}
			for _, e := range n.Out {
				stack = append(stack, e) // push
				if found := search(e.Callee); found != nil {
					return found
				}
				stack = stack[:len(stack)-1] // pop
			}
		}
		return nil
	}
	return search(start)
}

// PathsSearch returns all paths found from the start node
// to a node that matches the isMatch function. Under the hood,
// this is a depth first search.
//
// To find the first path (which may not be the shortest), use PathSearch.
func PathsSearch(start *callgraph.Node, isMatch func(*callgraph.Node) bool) Paths {
	var (
		paths = Paths{}

		stack = make(Path, 0, 32)
		seen  = make(map[*callgraph.Node]bool)

		search func(n *callgraph.Node)
	)

	search = func(n *callgraph.Node) {
		if n == nil {
			return
		}

		// debug("searching: %v\n", n)
		if !seen[n] {
			seen[n] = true
			if isMatch(n) {
				paths = append(paths, stack)

				stack = make(Path, 0, 32)
				seen = make(map[*callgraph.Node]bool)
				return
			}
			for _, e := range n.Out {
				// debug("\tout: %v\n", e)
				stack = append(stack, e) // push
				search(e.Callee)
				if len(stack) == 0 {
					continue
				}
				stack = stack[:len(stack)-1] // pop
			}
		}
	}
	search(start)

	return paths
}

// PathSearchCallTo returns the first path found from the start node
// to a node that matches the function name.
func PathSearchCallTo(start *callgraph.Node, fn string) Path {
	return PathSearch(start, func(n *callgraph.Node) bool {
		fnStr := n.Func.String()
		return fnStr == fn
	})
}

// PathsSearchCallTo returns the paths that call the given function name,
// which uses SSA function name syntax, e.g.: "(*database/sql.DB).Query".
func PathsSearchCallTo(start *callgraph.Node, fn string) Paths {
	return PathsSearch(start, func(n *callgraph.Node) bool {
		if n == nil || n.Func == nil {
			return false
		}
		fnStr := n.Func.String()
		return fnStr == fn
	})
}
