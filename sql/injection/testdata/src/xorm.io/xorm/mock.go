package xorm

type Engine struct{}

type Session struct{}

func (e *Engine) Query(...interface{})                                      {}
func (e *Engine) Exec(...interface{})                                       {}
func (e *Engine) QueryString(...interface{})                                {}
func (e *Engine) QueryInterface(...interface{})                             {}
func (e *Engine) SQL(interface{}, ...interface{}) *Session                  { return nil }
func (e *Engine) Where(interface{}, ...interface{}) *Session                { return nil }
func (e *Engine) And(interface{}, ...interface{}) *Session                  { return nil }
func (e *Engine) Or(interface{}, ...interface{}) *Session                   { return nil }
func (e *Engine) Alias(string) *Session                                     { return nil }
func (e *Engine) NotIn(string, ...interface{}) *Session                     { return nil }
func (e *Engine) In(string, ...interface{}) *Session                        { return nil }
func (e *Engine) Select(string) *Session                                    { return nil }
func (e *Engine) SetExpr(string, string) *Session                           { return nil }
func (e *Engine) OrderBy(string) *Session                                   { return nil }
func (e *Engine) Having(string) *Session                                    { return nil }
func (e *Engine) GroupBy(string) *Session                                   { return nil }
func (e *Engine) Join(string, interface{}, string, ...interface{}) *Session { return nil }

func (s *Session) Query(...interface{})                                      {}
func (s *Session) Exec(...interface{})                                       {}
func (s *Session) QueryString(...interface{})                                {}
func (s *Session) QueryInterface(...interface{})                             {}
func (s *Session) SQL(interface{}, ...interface{}) *Session                  { return nil }
func (s *Session) Where(interface{}, ...interface{}) *Session                { return nil }
func (s *Session) And(interface{}, ...interface{}) *Session                  { return nil }
func (s *Session) Or(interface{}, ...interface{}) *Session                   { return nil }
func (s *Session) Alias(string) *Session                                     { return nil }
func (s *Session) NotIn(string, ...interface{}) *Session                     { return nil }
func (s *Session) In(string, ...interface{}) *Session                        { return nil }
func (s *Session) Select(string) *Session                                    { return nil }
func (s *Session) SetExpr(string, string) *Session                           { return nil }
func (s *Session) OrderBy(string) *Session                                   { return nil }
func (s *Session) Having(string) *Session                                    { return nil }
func (s *Session) GroupBy(string) *Session                                   { return nil }
func (s *Session) Join(string, interface{}, string, ...interface{}) *Session { return nil }
