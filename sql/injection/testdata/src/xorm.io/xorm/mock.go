package xorm

// Engine is mocked from https://xorm.io/xorm
type Engine struct{}

// Session is mocked from https://xorm.io/xorm
type Session struct{}

// Query is a method that can be vulnerable to SQL injection
func (engine *Engine) Query(sqlStr string, args ...interface{}) {
}

// Exec is a method that can be vulnerable to SQL injection
func (engine *Engine) Exec(sqlStr string, args ...interface{}) {
}

// QueryString is a method that can be vulnerable to SQL injection
func (engine *Engine) QueryString(sqlStr string, args ...interface{}) {
}

// QueryInterface is a method that can be vulnerable to SQL injection
func (engine *Engine) QueryInterface(sqlStr string, args ...interface{}) {
}

// SQL is a method that can be vulnerable to SQL injection
func (engine *Engine) SQL(query string, args ...interface{}) *Session {
	return nil
}

// Where is a method that can be vulnerable to SQL injection
func (engine *Engine) Where(query string, args ...interface{}) *Session {
	return nil
}

// And is a method that can be vulnerable to SQL injection
func (engine *Engine) And(query string, args ...interface{}) *Session {
	return nil
}

// Or is a method that can be vulnerable to SQL injection
func (engine *Engine) Or(query string, args ...interface{}) *Session {
	return nil
}

// Alias is a method that can be vulnerable to SQL injection
func (engine *Engine) Alias(alias string) *Session {
	return nil
}

// NotIn is a method that can be vulnerable to SQL injection
func (engine *Engine) NotIn(column string, args ...interface{}) *Session {
	return nil
}

// In is a method that can be vulnerable to SQL injection
func (engine *Engine) In(column string, args ...interface{}) *Session {
	return nil
}

// Select is a method that can be vulnerable to SQL injection
func (engine *Engine) Select(str string) *Session {
	return nil
}

// SetExpr is a method that can be vulnerable to SQL injection
func (engine *Engine) SetExpr(column string, expression string) *Session {
	return nil
}

// OrderBy is a method that can be vulnerable to SQL injection
func (engine *Engine) OrderBy(order string) *Session {
	return nil
}

// Having is a method that can be vulnerable to SQL injection
func (engine *Engine) Having(conditions string) *Session {
	return nil
}

// GroupBy is a method that can be vulnerable to SQL injection
func (engine *Engine) GroupBy(keys string) *Session {
	return nil
}

// Join is a method that can be vulnerable to SQL injection
func (engine *Engine) Join(joinOperator string, tablename interface{}, condition string, args ...interface{}) *Session {
	return nil
}

// Session methods
func (session *Session) Query(sqlStr string, args ...interface{}) {
}

func (session *Session) Exec(sqlStr string, args ...interface{}) {
}

func (session *Session) QueryString(sqlStr string, args ...interface{}) {
}

func (session *Session) QueryInterface(sqlStr string, args ...interface{}) {
}

func (session *Session) SQL(query string, args ...interface{}) *Session {
	return nil
}

func (session *Session) Where(query string, args ...interface{}) *Session {
	return nil
}

func (session *Session) And(query string, args ...interface{}) *Session {
	return nil
}

func (session *Session) Or(query string, args ...interface{}) *Session {
	return nil
}

func (session *Session) Alias(alias string) *Session {
	return nil
}

func (session *Session) NotIn(column string, args ...interface{}) *Session {
	return nil
}

func (session *Session) In(column string, args ...interface{}) *Session {
	return nil
}

func (session *Session) Select(str string) *Session {
	return nil
}

func (session *Session) SetExpr(column string, expression string) *Session {
	return nil
}

func (session *Session) OrderBy(order string) *Session {
	return nil
}

func (session *Session) Having(conditions string) *Session {
	return nil
}

func (session *Session) GroupBy(keys string) *Session {
	return nil
}

func (session *Session) Join(joinOperator string, tablename interface{}, condition string, args ...interface{}) *Session {
	return nil
}