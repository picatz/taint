package pg

type DB struct{}

type Tx struct{}

type Result struct{}

func (db *DB) Query(dest interface{}, query string, params ...interface{}) (Result, error) {
	return Result{}, nil
}
func (db *DB) QueryOne(dest interface{}, query string, params ...interface{}) (Result, error) {
	return Result{}, nil
}
func (db *DB) Exec(query string, params ...interface{}) (Result, error)    { return Result{}, nil }
func (db *DB) ExecOne(query string, params ...interface{}) (Result, error) { return Result{}, nil }

func (tx *Tx) Query(dest interface{}, query string, params ...interface{}) (Result, error) {
	return Result{}, nil
}
func (tx *Tx) QueryOne(dest interface{}, query string, params ...interface{}) (Result, error) {
	return Result{}, nil
}
func (tx *Tx) Exec(query string, params ...interface{}) (Result, error)    { return Result{}, nil }
func (tx *Tx) ExecOne(query string, params ...interface{}) (Result, error) { return Result{}, nil }
