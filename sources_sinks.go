package taint

import (
	"golang.org/x/tools/go/ssa"
)

// valueSet is a set of ssa.Values that can be used to track
// the values that have been visited during a traversal. This
// is used to prevent infinite recursion, and to prevent
// visiting the same value multiple times.
type valueSet map[ssa.Value]struct{}

// includes returns true if the value is in the set.
func (v valueSet) includes(sv ssa.Value) bool {
	if v == nil {
		return false
	}
	_, ok := v[sv]
	return ok
}

// add adds the value to the set.
func (v valueSet) add(sv ssa.Value) {
	if v == nil {
		v = valueSet{}
	}
	v[sv] = struct{}{}
}

// stringSet is a set of unique strings that express
// the types of sources and sinks that are being
// tracked.
type stringSet map[string]struct{}

// includes returns true if the string is in the set.
func (t stringSet) includes(str string) (string, bool) {
	if t == nil {
		return "", false
	}
	_, ok := t[str]
	return str, ok
}

// Sources are the types that are considered "sources" of
// tainted data in the program.
type Sources = stringSet

// NewSources returns a new Sources set with the given
// source types.
func NewSources(sourceTypes ...string) Sources {
	srcs := Sources{}

	for _, src := range sourceTypes {
		srcs[src] = struct{}{}
	}

	return srcs
}

// Sinks are the types that are considered "sinks" that
// tainted data in the program may flow into.
type Sinks = stringSet

// NewSinks returns a new Sinks set with the given
// sink types.
func NewSinks(sinkTypes ...string) Sinks {
	snks := Sinks{}

	for _, snk := range sinkTypes {
		snks[snk] = struct{}{}
	}

	return snks
}
