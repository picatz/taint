package sqlite

type dialector struct{}

type Dialector = dialector

func Open(dsn string) Dialector { return dialector{} }
