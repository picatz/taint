package callgraphutil

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// LogLevel represents different levels of logging detail
type LogLevel int

const (
	LogLevelSilent LogLevel = iota
	LogLevelInfo
	LogLevelDebug
	LogLevelTrace
)

// Logger provides structured logging for call graph operations
type Logger struct {
	level  LogLevel
	writer io.Writer
	prefix string
}

// LoggerKey is the context key for logger instances
type loggerKey struct{}

// NewLogger creates a new logger with the specified level and output
func NewLogger(level LogLevel, writer io.Writer) *Logger {
	if writer == nil {
		writer = os.Stderr
	}
	return &Logger{
		level:  level,
		writer: writer,
		prefix: "",
	}
}

// WithPrefix returns a new logger with an additional prefix
func (l *Logger) WithPrefix(prefix string) *Logger {
	newPrefix := prefix
	if l.prefix != "" {
		newPrefix = l.prefix + " " + prefix
	}
	return &Logger{
		level:  l.level,
		writer: l.writer,
		prefix: newPrefix,
	}
}

// Info logs informational messages (always visible except silent mode)
func (l *Logger) Info(format string, args ...interface{}) {
	if l.level >= LogLevelInfo {
		l.log("•", format, args...)
	}
}

// Debug logs debug messages (visible in debug and trace modes)
func (l *Logger) Debug(format string, args ...interface{}) {
	if l.level >= LogLevelDebug {
		l.log("→", format, args...)
	}
}

// Trace logs detailed trace messages (visible only in trace mode)
func (l *Logger) Trace(format string, args ...interface{}) {
	if l.level >= LogLevelTrace {
		l.log("·", format, args...)
	}
}

// Progress logs progress information with timing
func (l *Logger) Progress(operation string, current, total int, elapsed time.Duration) {
	if l.level >= LogLevelInfo {
		if total > 0 {
			percent := float64(current) / float64(total) * 100
			l.log("▸", "%s: %d/%d (%.1f%%) [%v]", operation, current, total, percent, elapsed.Truncate(time.Millisecond))
		} else {
			l.log("▸", "%s: %d processed [%v]", operation, current, elapsed.Truncate(time.Millisecond))
		}
	}
}

// Step logs a processing step with context
func (l *Logger) Step(step string, details ...string) {
	if l.level >= LogLevelInfo {
		msg := step
		if len(details) > 0 {
			msg += ": " + strings.Join(details, ", ")
		}
		l.log("✓", "%s", msg)
	}
}

// Warning logs warning messages
func (l *Logger) Warning(format string, args ...interface{}) {
	if l.level >= LogLevelInfo {
		l.log("⚠", format, args...)
	}
}

// Error logs error messages (always visible except silent mode)
func (l *Logger) Error(format string, args ...interface{}) {
	if l.level >= LogLevelInfo {
		l.log("✗", format, args...)
	}
}

// log is the internal logging function
func (l *Logger) log(symbol, format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	prefix := ""
	if l.prefix != "" {
		prefix = "[" + l.prefix + "] "
	}
	fmt.Fprintf(l.writer, "%s %s%s\n", symbol, prefix, message)
	if f, ok := l.writer.(interface{ Flush() error }); ok {
		_ = f.Flush()
	}
}

// WithLogger adds a logger to the context
func WithLogger(ctx context.Context, logger *Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

// FromContext retrieves a logger from the context, returning a no-op logger if none exists
func FromContext(ctx context.Context) *Logger {
	if logger, ok := ctx.Value(loggerKey{}).(*Logger); ok {
		return logger
	}
	// Return a silent logger if none is in context
	return NewLogger(LogLevelSilent, io.Discard)
}

// ProgressTracker tracks progress of long-running operations with intelligent batching
type ProgressTracker struct {
	name      string
	total     int
	current   int
	startTime time.Time
	logger    *Logger
	lastLog   time.Time
	interval  time.Duration
	batchSize int
	lastBatch int
}

// NewProgressTracker creates a new progress tracker
func NewProgressTracker(ctx context.Context, name string, total int) *ProgressTracker {
	logger := FromContext(ctx)

	// Smart batching: fewer updates for larger datasets
	batchSize := 1
	interval := 1 * time.Second

	if total > 1000 {
		batchSize = total / 10 // 10 updates max
		interval = 3 * time.Second
	} else if total > 100 {
		batchSize = total / 20 // 20 updates max
		interval = 2 * time.Second
	}

	tracker := &ProgressTracker{
		name:      name,
		total:     total,
		startTime: time.Now(),
		logger:    logger,
		lastLog:   time.Now(),
		interval:  interval,
		batchSize: batchSize,
	}

	// Only log start for significant operations
	if total > 10 {
		logger.Info("→ Starting %s (%d items)", name, total)
	}

	return tracker
}

// Update increments progress and logs intelligently
func (pt *ProgressTracker) Update(message string) {
	pt.current++

	now := time.Now()
	shouldLog := false

	// Log on completion
	if pt.current == pt.total {
		shouldLog = true
	} else {
		// Log based on batch size or time interval
		timePassed := now.Sub(pt.lastLog) >= pt.interval
		batchComplete := pt.current-pt.lastBatch >= pt.batchSize

		// Also log on significant milestones (25%, 50%, 75%)
		percentage := float64(pt.current) / float64(pt.total)
		milestone := percentage >= 0.25 && (pt.current-pt.lastBatch) >= pt.batchSize/4 ||
			percentage >= 0.5 && (pt.current-pt.lastBatch) >= pt.batchSize/2 ||
			percentage >= 0.75 && (pt.current-pt.lastBatch) >= pt.batchSize*3/4

		shouldLog = timePassed || batchComplete || milestone
	}

	if shouldLog {
		elapsed := now.Sub(pt.startTime)
		percentage := float64(pt.current) / float64(pt.total) * 100

		if pt.current == pt.total {
			pt.logger.Info("✓ %s complete (%d items) in %v", pt.name, pt.current, elapsed.Truncate(10*time.Millisecond))
		} else if pt.total > 10 { // Only show progress for significant operations
			rate := float64(pt.current) / elapsed.Seconds()
			eta := time.Duration(float64(pt.total-pt.current) / rate * float64(time.Second))

			pt.logger.Info("▶ %s: %d/%d (%.0f%%) - ETA: %v",
				pt.name, pt.current, pt.total, percentage, eta.Round(time.Second))
		}

		pt.lastLog = now
		pt.lastBatch = pt.current
	}

	// Debug level shows every item
	pt.logger.Debug("Processing %s (%d/%d): %s", pt.name, pt.current, pt.total, message)
}

// Complete marks the operation as finished
func (pt *ProgressTracker) Complete() {
	if pt.current < pt.total {
		pt.current = pt.total
		elapsed := time.Since(pt.startTime)
		pt.logger.Info("✓ %s complete (%d items) in %v", pt.name, pt.current, elapsed.Truncate(10*time.Millisecond))
	}
}
