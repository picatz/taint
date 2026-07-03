// Package modelflag adds a shared -models flag to the detector analyzers and
// loads the user-supplied taint models it names, so every CLI extends the
// built-in rules the same way.
package modelflag

import (
	"flag"

	"github.com/picatz/taint"
)

// Flag is a registered -models flag. The zero value is ready to Register.
type Flag struct {
	path string
}

// Register adds the -models flag to fs.
func (f *Flag) Register(fs *flag.FlagSet) {
	fs.StringVar(&f.path, "models", "",
		"path to a YAML file or directory of taint models to load in addition to the built-in rules")
}

// Load parses the models named by the flag. An unset flag returns nil, nil.
func (f *Flag) Load() ([]taint.Model, error) {
	return taint.ModelsFromPath(f.path)
}
