package gorqlite

type Connection struct{}

func Open(addr string) (*Connection, error) { return nil, nil }

func (c *Connection) Query(dest interface{}, query string, args ...interface{}) error    { return nil }
func (c *Connection) QueryOne(dest interface{}, query string, args ...interface{}) error { return nil }
func (c *Connection) Write(query string, args ...interface{}) error                      { return nil }
func (c *Connection) WriteOne(query string, args ...interface{}) error                   { return nil }
