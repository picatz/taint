package glog

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
