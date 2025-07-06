package nested

import (
	"database/sql"
)

func Run(db *sql.DB, query string) error {
	_, err := db.Query(query) // want "potential sql injection"
	if err != nil {
		return err
	}
	return nil
}
