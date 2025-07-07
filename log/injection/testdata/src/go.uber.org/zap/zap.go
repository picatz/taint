package zap

func NewProduction() (*Logger, error) { return &Logger{}, nil }

type Logger struct{}

func (l *Logger) Info(msg string, fields ...Field)   {}
func (l *Logger) Debug(msg string, fields ...Field)  {}
func (l *Logger) Warn(msg string, fields ...Field)   {}
func (l *Logger) Error(msg string, fields ...Field)  {}
func (l *Logger) DPanic(msg string, fields ...Field) {}
func (l *Logger) Panic(msg string, fields ...Field)  {}
func (l *Logger) Fatal(msg string, fields ...Field)  {}

type SugaredLogger struct{}

func (s *SugaredLogger) Debug(args ...interface{})  {}
func (s *SugaredLogger) Info(args ...interface{})   {}
func (s *SugaredLogger) Warn(args ...interface{})   {}
func (s *SugaredLogger) Error(args ...interface{})  {}
func (s *SugaredLogger) DPanic(args ...interface{}) {}
func (s *SugaredLogger) Panic(args ...interface{})  {}
func (s *SugaredLogger) Fatal(args ...interface{})  {}

type Field struct{}

func String(key, val string) Field { return Field{} }
