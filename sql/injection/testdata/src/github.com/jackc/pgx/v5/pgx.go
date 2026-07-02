// Package pgx is a minimal stand-in for github.com/jackc/pgx/v5, providing
// just enough of the surface (Conn, Tx, and the query methods) for taint
// analysistest fixtures to typecheck. It is not the real driver.
package pgx

import "context"

type Rows interface{ Close() }

type Row interface{ Scan(dest ...any) error }

type CommandTag struct{}

// Conn mirrors *pgx.Conn's query surface.
type Conn struct{}

func Connect(ctx context.Context, connString string) (*Conn, error) { return &Conn{}, nil }

func (c *Conn) Query(ctx context.Context, sql string, args ...any) (Rows, error) {
	return nil, nil
}

func (c *Conn) QueryRow(ctx context.Context, sql string, args ...any) Row { return nil }

func (c *Conn) Exec(ctx context.Context, sql string, args ...any) (CommandTag, error) {
	return CommandTag{}, nil
}

func (c *Conn) Prepare(ctx context.Context, name, sql string) (any, error) { return nil, nil }

// Tx mirrors the pgx.Tx interface's query surface.
type Tx interface {
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) Row
	Exec(ctx context.Context, sql string, args ...any) (CommandTag, error)
	Prepare(ctx context.Context, name, sql string) (any, error)
}

func (c *Conn) Begin(ctx context.Context) (Tx, error) { return nil, nil }
