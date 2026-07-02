// Package pgxpool is a minimal stand-in for github.com/jackc/pgx/v5/pgxpool,
// providing just enough of Pool's query surface for taint analysistest
// fixtures to typecheck. It is not the real pool implementation.
package pgxpool

import "context"

type Rows interface{ Close() }

type Row interface{ Scan(dest ...any) error }

type CommandTag struct{}

// Pool mirrors *pgxpool.Pool's query surface.
type Pool struct{}

func New(ctx context.Context, connString string) (*Pool, error) { return &Pool{}, nil }

func (p *Pool) Query(ctx context.Context, sql string, args ...any) (Rows, error) {
	return nil, nil
}

func (p *Pool) QueryRow(ctx context.Context, sql string, args ...any) Row { return nil }

func (p *Pool) Exec(ctx context.Context, sql string, args ...any) (CommandTag, error) {
	return CommandTag{}, nil
}
