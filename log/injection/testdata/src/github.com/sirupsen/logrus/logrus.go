package logrus

func Debug(args ...interface{}) {}
func Info(args ...interface{})  {}
func Warn(args ...interface{})  {}
func Error(args ...interface{}) {}
func Fatal(args ...interface{}) {}
func Panic(args ...interface{}) {}

type Logger struct{}

func (l *Logger) Debug(args ...interface{}) {}
func (l *Logger) Info(args ...interface{})  {}
func (l *Logger) Warn(args ...interface{})  {}
func (l *Logger) Error(args ...interface{}) {}
func (l *Logger) Fatal(args ...interface{}) {}
func (l *Logger) Panic(args ...interface{}) {}
