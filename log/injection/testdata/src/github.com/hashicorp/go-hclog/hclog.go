package hclog

type Logger struct{}

type LoggerOptions struct{}

func New(opts *LoggerOptions) *Logger { return &Logger{} }

func (l *Logger) Trace(msg string, args ...interface{}) {}
func (l *Logger) Debug(msg string, args ...interface{}) {}
func (l *Logger) Info(msg string, args ...interface{})  {}
func (l *Logger) Warn(msg string, args ...interface{})  {}
func (l *Logger) Error(msg string, args ...interface{}) {}
func (l *Logger) Named(name string) *Logger             { return l }
