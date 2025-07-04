package gorm

// DB is mocked from https://gorm.io/gorm
type DB struct{}

// Where is a method that can be vulnerable to SQL injection
func (s *DB) Where(query interface{}, args ...interface{}) *DB {
	return nil
}

// Or is a method that can be vulnerable to SQL injection
func (s *DB) Or(query interface{}, args ...interface{}) *DB {
	return nil
}

// Not is a method that can be vulnerable to SQL injection
func (s *DB) Not(query interface{}, args ...interface{}) *DB {
	return nil
}

// Group is a method that can be vulnerable to SQL injection
func (s *DB) Group(name string) *DB {
	return nil
}

// Having is a method that can be vulnerable to SQL injection
func (s *DB) Having(query interface{}, args ...interface{}) *DB {
	return nil
}

// Joins is a method that can be vulnerable to SQL injection
func (s *DB) Joins(query string, args ...interface{}) *DB {
	return nil
}

// Select is a method that can be vulnerable to SQL injection
func (s *DB) Select(query interface{}, args ...interface{}) *DB {
	return nil
}

// Distinct is a method that can be vulnerable to SQL injection
func (s *DB) Distinct(args ...interface{}) *DB {
	return nil
}

// Pluck is a method that can be vulnerable to SQL injection
func (s *DB) Pluck(column string, dest interface{}) *DB {
	return nil
}

// Raw is a method that can be vulnerable to SQL injection
func (s *DB) Raw(sql string, values ...interface{}) *DB {
	return nil
}

// Exec is a method that can be vulnerable to SQL injection
func (s *DB) Exec(sql string, values ...interface{}) *DB {
	return nil
}

// Order is a method that can be vulnerable to SQL injection
func (s *DB) Order(value interface{}) *DB {
	return nil
}

// Table is a method that can be vulnerable to SQL injection
func (s *DB) Table(name string, args ...interface{}) *DB {
	return nil
}