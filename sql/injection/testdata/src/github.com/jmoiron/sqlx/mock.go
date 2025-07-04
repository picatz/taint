package sqlx

// DB is mocked from https://github.com/jmoiron/sqlx
type DB struct{}

// Tx is mocked from https://github.com/jmoiron/sqlx
type Tx struct{}

// Select is a method that can be vulnerable to SQL injection
func (db *DB) Select(dest interface{}, query string, args ...interface{}) error {
	return nil
}

// Get is a method that can be vulnerable to SQL injection
func (db *DB) Get(dest interface{}, query string, args ...interface{}) error {
	return nil
}

// MustExec is a method that can be vulnerable to SQL injection
func (db *DB) MustExec(query string, args ...interface{}) {
}

// Queryx is a method that can be vulnerable to SQL injection
func (db *DB) Queryx(query string, args ...interface{}) *Rows {
	return nil
}

// NamedExec is a method that can be vulnerable to SQL injection
func (db *DB) NamedExec(query string, arg interface{}) error {
	return nil
}

// NamedQuery is a method that can be vulnerable to SQL injection
func (db *DB) NamedQuery(query string, arg interface{}) (*Rows, error) {
	return nil, nil
}

// Select is a method that can be vulnerable to SQL injection
func (tx *Tx) Select(dest interface{}, query string, args ...interface{}) error {
	return nil
}

// Get is a method that can be vulnerable to SQL injection
func (tx *Tx) Get(dest interface{}, query string, args ...interface{}) error {
	return nil
}

// MustExec is a method that can be vulnerable to SQL injection
func (tx *Tx) MustExec(query string, args ...interface{}) {
}

// Queryx is a method that can be vulnerable to SQL injection
func (tx *Tx) Queryx(query string, args ...interface{}) *Rows {
	return nil
}

// NamedExec is a method that can be vulnerable to SQL injection
func (tx *Tx) NamedExec(query string, arg interface{}) error {
	return nil
}

// NamedQuery is a method that can be vulnerable to SQL injection
func (tx *Tx) NamedQuery(query string, arg interface{}) (*Rows, error) {
	return nil, nil
}

// Rows is a mock struct
type Rows struct{}