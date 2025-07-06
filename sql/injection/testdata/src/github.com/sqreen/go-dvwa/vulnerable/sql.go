package vulnerable

import (
	"context"
	"database/sql"
)

type Product struct {
	ID       int
	Name     string
	Category string
}

func PrepareSQLDB() (*sql.DB, error) { return nil, nil }

func GetProducts(ctx context.Context, db *sql.DB, category string) ([]Product, error) {
	rows, err := db.QueryContext(ctx, "SELECT * FROM product WHERE category='"+category+"'") // want "potential sql injection"
	if err != nil {
		return nil, err
	}
	_ = rows
	return nil, nil
}
