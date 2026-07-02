// Package klog is a minimal stand-in for k8s.io/klog/v2, providing just enough
// of the package-level logging functions for taint analysistest fixtures to
// typecheck. It is not the real logger.
package klog

func Info(args ...any)                                   {}
func Infof(format string, args ...any)                   {}
func Infoln(args ...any)                                 {}
func InfoS(msg string, keysAndValues ...any)             {}
func Warning(args ...any)                                {}
func Warningf(format string, args ...any)                {}
func Warningln(args ...any)                              {}
func Error(args ...any)                                  {}
func Errorf(format string, args ...any)                  {}
func Errorln(args ...any)                                {}
func ErrorS(err error, msg string, keysAndValues ...any) {}
func Fatal(args ...any)                                  {}
func Fatalf(format string, args ...any)                  {}
func Fatalln(args ...any)                                {}
