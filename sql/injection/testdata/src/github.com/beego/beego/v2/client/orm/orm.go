// Package orm is a minimal stand-in for github.com/beego/beego/v2/client/orm,
// providing just enough of the Ormer/DML raw-query surface for taint
// analysistest fixtures to typecheck. It mirrors the real structure where Raw
// is declared on DML and Ormer embeds DML.
package orm

import "context"

type RawSeter interface {
	Exec() (any, error)
	QueryRows(containers ...any) (int64, error)
}

// DML declares the raw-SQL query methods, matching real beego.
type DML interface {
	Raw(query string, args ...interface{}) RawSeter
	RawWithCtx(ctx context.Context, query string, args ...interface{}) RawSeter
}

// Ormer embeds DML, so ormer.Raw / ormer.RawWithCtx are promoted methods.
type Ormer interface {
	DML
}

// ormer is a concrete implementation of Ormer, so NewOrm returns a concrete
// type through the Ormer interface (as real beego does).
type ormer struct{}

func (o *ormer) Raw(query string, args ...interface{}) RawSeter { return nil }
func (o *ormer) RawWithCtx(ctx context.Context, query string, args ...interface{}) RawSeter {
	return nil
}

func NewOrm() Ormer { return &ormer{} }
