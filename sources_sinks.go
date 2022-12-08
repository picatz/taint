package taint

import (
	"golang.org/x/tools/go/ssa"
)

type valueSet map[ssa.Value]struct{}

func (v valueSet) includes(sv ssa.Value) bool {
	if v == nil {
		return false
	}
	_, ok := v[sv]
	return ok
}

func (v valueSet) add(sv ssa.Value) {
	if v == nil {
		v = valueSet{}
	}
	v[sv] = struct{}{}
}

type stringSet map[string]struct{}

func (t stringSet) includes(str string) (string, bool) {
	if t == nil {
		return "", false
	}
	_, ok := t[str]
	return str, ok
}

type Sources = stringSet

func NewSources(sourceTypes ...string) Sources {
	srcs := Sources{}

	for _, src := range sourceTypes {
		srcs[src] = struct{}{}
	}

	return srcs
}

type Sinks = stringSet

func NewSinks(sinkTypes ...string) Sinks {
	snks := Sinks{}

	for _, snk := range sinkTypes {
		snks[snk] = struct{}{}
	}

	return snks
}
