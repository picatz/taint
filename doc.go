// Package taint enables "taint checking", a static analysis technique
// for identifying attacker-controlled "sources" used in dangerous
// contexts "sinks".
//
// A classic example of this is identifying SQL injections,
// where user controlled inputs, typically from an HTTP request,
// finds their way into a SQL query without using a prepared statement.
package taint
