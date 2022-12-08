package gorm

// Model is mocked from https://github.com/jinzhu/gorm/blob/5c235b72a414e448d1f441aba24a47fd6eb976f4/model.go#L9
type Model struct{}

// DB is mocked from https://github.com/jinzhu/gorm/blob/5c235b72a414e448d1f441aba24a47fd6eb976f4/main.go#L15
type DB struct{}

// Open is mocked from https://github.com/jinzhu/gorm/blob/5c235b72a414e448d1f441aba24a47fd6eb976f4/main.go#L58
func Open(dialect string, args ...interface{}) (db *DB, err error) {
	return nil, nil
}

// Where is mocked from https://github.com/jinzhu/gorm/blob/5c235b72a414e448d1f441aba24a47fd6eb976f4/main.go#L237
func (s *DB) Where(query interface{}, args ...interface{}) *DB {
	return nil
}

// Or is mocked from https://github.com/jinzhu/gorm/blob/5c235b72a414e448d1f441aba24a47fd6eb976f4/main.go#L242
func (s *DB) Or(query interface{}, args ...interface{}) *DB {
	return nil
}

// Not is mocked from https://github.com/jinzhu/gorm/blob/5c235b72a414e448d1f441aba24a47fd6eb976f4/main.go#L247
func (s *DB) Not(query interface{}, args ...interface{}) *DB {
	return nil
}

// Find is mocked from https://github.com/jinzhu/gorm/blob/5c235b72a414e448d1f441aba24a47fd6eb976f4/main.go#L356
func (s *DB) Find(out interface{}, where ...interface{}) *DB {
	return nil
}

// Take is mocked from https://github.com/jinzhu/gorm/blob/5c235b72a414e448d1f441aba24a47fd6eb976f4/main.go#L341
func (s *DB) Take(out interface{}, where ...interface{}) *DB {
	return nil
}

// First is mocked from https://github.com/jinzhu/gorm/blob/5c235b72a414e448d1f441aba24a47fd6eb976f4/main.go#L332
func (s *DB) First(out interface{}, where ...interface{}) *DB {
	return nil
}

// Take is mocked from https://github.com/jinzhu/gorm/blob/5c235b72a414e448d1f441aba24a47fd6eb976f4/main.go#L348
func (s *DB) Last(out interface{}, where ...interface{}) *DB {
	return nil
}

// Delete is mocked from https://github.com/jinzhu/gorm/blob/5c235b72a414e448d1f441aba24a47fd6eb976f4/main.go#L491
func (s *DB) Delete(value interface{}, where ...interface{}) *DB {
	return nil
}
