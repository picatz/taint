package sqlx

type DB struct{}

type Tx struct{}

type Row struct{}

type Rows struct{}

type Result interface{}

func Open(driverName, dataSourceName string) (*DB, error)    { return nil, nil }
func Connect(driverName, dataSourceName string) (*DB, error) { return nil, nil }

func (db *DB) Query(query string, args ...interface{}) (*Rows, error)           { return nil, nil }
func (db *DB) Queryx(query string, args ...interface{}) (*Rows, error)          { return nil, nil }
func (db *DB) QueryRow(query string, args ...interface{}) *Row                  { return nil }
func (db *DB) QueryRowx(query string, args ...interface{}) *Row                 { return nil }
func (db *DB) Select(dest interface{}, query string, args ...interface{}) error { return nil }
func (db *DB) Get(dest interface{}, query string, args ...interface{}) error    { return nil }
func (db *DB) Exec(query string, args ...interface{}) (Result, error)           { return nil, nil }

func (tx *Tx) Query(query string, args ...interface{}) (*Rows, error)           { return nil, nil }
func (tx *Tx) Queryx(query string, args ...interface{}) (*Rows, error)          { return nil, nil }
func (tx *Tx) QueryRow(query string, args ...interface{}) *Row                  { return nil }
func (tx *Tx) QueryRowx(query string, args ...interface{}) *Row                 { return nil }
func (tx *Tx) Select(dest interface{}, query string, args ...interface{}) error { return nil }
func (tx *Tx) Get(dest interface{}, query string, args ...interface{}) error    { return nil }
func (tx *Tx) Exec(query string, args ...interface{}) (Result, error)           { return nil, nil }
