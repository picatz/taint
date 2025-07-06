package squirrel

type Sqlizer interface{}

func Expr(sql string, args ...interface{}) Sqlizer { return nil }
