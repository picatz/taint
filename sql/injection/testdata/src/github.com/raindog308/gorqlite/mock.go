package gorqlite

// The real gorqlite API takes SQL statements directly: Query/Write take a
// []string of statements, QueryOne/WriteOne take a single statement string.
// There are no bound-parameter arguments.

type Connection struct{}

type QueryResult struct{}

type WriteResult struct{}

func Open(addr string) (*Connection, error) { return nil, nil }

func (c *Connection) Query(sqlStatements []string) ([]QueryResult, error) { return nil, nil }
func (c *Connection) QueryOne(sqlStatement string) (QueryResult, error)   { return QueryResult{}, nil }
func (c *Connection) Write(sqlStatements []string) ([]WriteResult, error) { return nil, nil }
func (c *Connection) WriteOne(sqlStatement string) (WriteResult, error)   { return WriteResult{}, nil }
