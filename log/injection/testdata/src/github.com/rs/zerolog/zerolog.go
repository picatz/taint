// Package zerolog is a minimal stand-in for github.com/rs/zerolog, providing
// just enough of the Logger/Event chain for taint analysistest fixtures to
// typecheck. It is not the real logger.
package zerolog

import "io"

type Event struct{}

func (e *Event) Str(key, val string) *Event   { return e }
func (e *Event) Msg(msg string)               {}
func (e *Event) Msgf(format string, v ...any) {}
func (e *Event) Send()                        {}

type Logger struct{}

func New(w io.Writer) Logger { return Logger{} }

func (l *Logger) Info() *Event  { return &Event{} }
func (l *Logger) Warn() *Event  { return &Event{} }
func (l *Logger) Error() *Event { return &Event{} }
func (l *Logger) Debug() *Event { return &Event{} }
