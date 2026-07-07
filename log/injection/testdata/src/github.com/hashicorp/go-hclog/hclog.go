package hclog

// Logger mirrors the real go-hclog Logger, which is an interface. Modeling it
// as a struct would make real interface-dispatched calls miss the sink model.
type Logger interface {
	Trace(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Named(name string) Logger
}

type LoggerOptions struct{}

func New(opts *LoggerOptions) Logger { return nil }
