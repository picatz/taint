package gorm

type Model struct{}

type DB struct{}

type Config struct{}

type Dialector interface{}

func Open(d Dialector, config *Config) (*DB, error) { return nil, nil }

func (s *DB) Where(query interface{}, args ...interface{}) *DB  { return nil }
func (s *DB) Or(query interface{}, args ...interface{}) *DB     { return nil }
func (s *DB) Not(query interface{}, args ...interface{}) *DB    { return nil }
func (s *DB) Group(query string) *DB                            { return nil }
func (s *DB) Having(query interface{}, args ...interface{}) *DB { return nil }
func (s *DB) Joins(query string, args ...interface{}) *DB       { return nil }
func (s *DB) Select(query interface{}, args ...interface{}) *DB { return nil }
func (s *DB) Distinct(args ...interface{}) *DB                  { return nil }
func (s *DB) Pluck(column string, value interface{}) *DB        { return nil }
func (s *DB) Raw(sql string, values ...interface{}) *DB         { return nil }
func (s *DB) Exec(sql string, values ...interface{}) *DB        { return nil }
func (s *DB) Order(value interface{}) *DB                       { return nil }
func (s *DB) Find(dest interface{}, conds ...interface{}) *DB   { return nil }
