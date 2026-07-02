package glog

import "context"

func Info(args ...interface{})                    {}
func Infoln(args ...interface{})                  {}
func Infof(format string, args ...interface{})    {}
func Warning(args ...interface{})                 {}
func Warningln(args ...interface{})               {}
func Warningf(format string, args ...interface{}) {}
func Error(args ...interface{})                   {}
func Errorln(args ...interface{})                 {}
func Errorf(format string, args ...interface{})   {}
func Fatal(args ...interface{})                   {}
func Fatalln(args ...interface{})                 {}
func Fatalf(format string, args ...interface{})   {}

// Depth variants.
func InfoDepth(depth int, args ...interface{})                    {}
func InfoDepthf(depth int, format string, args ...interface{})    {}
func WarningDepth(depth int, args ...interface{})                 {}
func WarningDepthf(depth int, format string, args ...interface{}) {}
func ErrorDepth(depth int, args ...interface{})                   {}
func ErrorDepthf(depth int, format string, args ...interface{})   {}
func FatalDepth(depth int, args ...interface{})                   {}
func FatalDepthf(depth int, format string, args ...interface{})   {}

// Context variants.
func InfoContext(ctx context.Context, args ...interface{})                                    {}
func InfoContextf(ctx context.Context, format string, args ...interface{})                    {}
func InfoContextDepth(ctx context.Context, depth int, args ...interface{})                    {}
func InfoContextDepthf(ctx context.Context, depth int, format string, args ...interface{})    {}
func WarningContext(ctx context.Context, args ...interface{})                                 {}
func WarningContextf(ctx context.Context, format string, args ...interface{})                 {}
func WarningContextDepth(ctx context.Context, depth int, args ...interface{})                 {}
func WarningContextDepthf(ctx context.Context, depth int, format string, args ...interface{}) {}
func ErrorContext(ctx context.Context, args ...interface{})                                   {}
func ErrorContextf(ctx context.Context, format string, args ...interface{})                   {}
func ErrorContextDepth(ctx context.Context, depth int, args ...interface{})                   {}
func ErrorContextDepthf(ctx context.Context, depth int, format string, args ...interface{})   {}
func FatalContext(ctx context.Context, args ...interface{})                                   {}
func FatalContextf(ctx context.Context, format string, args ...interface{})                   {}
func FatalContextDepth(ctx context.Context, depth int, args ...interface{})                   {}
func FatalContextDepthf(ctx context.Context, depth int, format string, args ...interface{})   {}

// Exit family (logs args, then exits).
func Exit(args ...interface{})                                                             {}
func Exitf(format string, args ...interface{})                                             {}
func Exitln(args ...interface{})                                                           {}
func ExitDepth(depth int, args ...interface{})                                             {}
func ExitDepthf(depth int, format string, args ...interface{})                             {}
func ExitContext(ctx context.Context, args ...interface{})                                 {}
func ExitContextf(ctx context.Context, format string, args ...interface{})                 {}
func ExitContextDepth(ctx context.Context, depth int, args ...interface{})                 {}
func ExitContextDepthf(ctx context.Context, depth int, format string, args ...interface{}) {}

type Verbose bool

func V(level int) Verbose                                                                          { return Verbose(true) }
func (v Verbose) Info(args ...interface{})                                                         {}
func (v Verbose) Infoln(args ...interface{})                                                       {}
func (v Verbose) Infof(format string, args ...interface{})                                         {}
func (v Verbose) InfoDepth(depth int, args ...interface{})                                         {}
func (v Verbose) InfoDepthf(depth int, format string, args ...interface{})                         {}
func (v Verbose) InfoContext(ctx interface{}, args ...interface{})                                 {}
func (v Verbose) InfoContextf(ctx interface{}, format string, args ...interface{})                 {}
func (v Verbose) InfoContextDepth(ctx interface{}, depth int, args ...interface{})                 {}
func (v Verbose) InfoContextDepthf(ctx interface{}, depth int, format string, args ...interface{}) {}
