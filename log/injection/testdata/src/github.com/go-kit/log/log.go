// Package log is a minimal stand-in for github.com/go-kit/log, providing just
// enough of the Logger interface for taint analysistest fixtures to typecheck.
// It is not the real logger.
package log

import "io"

// Logger mirrors go-kit's structured Logger.
type Logger interface {
	Log(keyvals ...interface{}) error
}

func NewLogfmtLogger(w io.Writer) Logger { return nopLogger{} }
func NewJSONLogger(w io.Writer) Logger   { return nopLogger{} }
func NewNopLogger() Logger               { return nopLogger{} }

type nopLogger struct{}

func (nopLogger) Log(keyvals ...interface{}) error { return nil }
