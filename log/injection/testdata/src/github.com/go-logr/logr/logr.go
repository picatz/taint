// Package logr is a minimal stand-in for github.com/go-logr/logr, providing
// just enough of the value-receiver Logger for taint analysistest fixtures to
// typecheck. It is not the real logging facade.
package logr

type LogSink interface{}

// Logger is a value type in real logr; its methods use value receivers.
type Logger struct{}

func New(sink LogSink) Logger { return Logger{} }

func (l Logger) Info(msg string, keysAndValues ...any)             {}
func (l Logger) Error(err error, msg string, keysAndValues ...any) {}
