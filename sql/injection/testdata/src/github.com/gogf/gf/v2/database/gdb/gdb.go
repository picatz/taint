// Package gdb is a minimal stand-in for github.com/gogf/gf/v2/database/gdb,
// providing just enough of the DB interface for taint analysistest fixtures to
// typecheck. It is not the real driver.
package gdb

import (
	"context"
	"database/sql"
)

type Record map[string]any

type Result []Record

type Model struct{}

// DB mirrors the raw-SQL surface of gdb.DB.
type DB interface {
	Query(ctx context.Context, sql string, args ...any) (Result, error)
	Exec(ctx context.Context, sql string, args ...any) (sql.Result, error)
	GetAll(ctx context.Context, sql string, args ...any) (Result, error)
	GetOne(ctx context.Context, sql string, args ...any) (Record, error)
	Raw(rawSql string, args ...any) *Model
}

// core is a concrete implementation of DB, mirroring gdb's *Core so that
// callers obtain a concrete type through the DB interface (as real gdb does).
type core struct{}

func (c *core) Query(ctx context.Context, sql string, args ...any) (Result, error) {
	return nil, nil
}
func (c *core) Exec(ctx context.Context, sql string, args ...any) (sql.Result, error) {
	return nil, nil
}
func (c *core) GetAll(ctx context.Context, sql string, args ...any) (Result, error) {
	return nil, nil
}
func (c *core) GetOne(ctx context.Context, sql string, args ...any) (Record, error) {
	return nil, nil
}
func (c *core) Raw(rawSql string, args ...any) *Model { return nil }

func Instance(name ...string) (DB, error) { return &core{}, nil }
