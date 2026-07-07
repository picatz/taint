package pg

type DB struct{}

type Tx struct{}

type Result struct{}

// The real go-pg query/exec channel is interface{}, not string, so a constant
// query boxes to a MakeInterface. Mirror that so the tests exercise the real
// SSA shape.
func (db *DB) Query(model, query interface{}, params ...interface{}) (Result, error) {
	return Result{}, nil
}
func (db *DB) QueryOne(model, query interface{}, params ...interface{}) (Result, error) {
	return Result{}, nil
}
func (db *DB) Exec(query interface{}, params ...interface{}) (Result, error)    { return Result{}, nil }
func (db *DB) ExecOne(query interface{}, params ...interface{}) (Result, error) { return Result{}, nil }

func (tx *Tx) Query(model, query interface{}, params ...interface{}) (Result, error) {
	return Result{}, nil
}
func (tx *Tx) QueryOne(model, query interface{}, params ...interface{}) (Result, error) {
	return Result{}, nil
}
func (tx *Tx) Exec(query interface{}, params ...interface{}) (Result, error)    { return Result{}, nil }
func (tx *Tx) ExecOne(query interface{}, params ...interface{}) (Result, error) { return Result{}, nil }
