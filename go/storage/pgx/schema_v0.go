package pgx

import (
	"fmt"

	"github.com/jackc/pgx"
	"github.com/pkg/errors"
)

func initSchemaV0(db *pgx.ConnPool) error {
	var version int
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS metadata (version INT)"); err != nil {
		return errors.Wrap(err, "storage/pgx: failed to create metadata table")
	}
	err := db.QueryRow("SELECT version FROM metadata").Scan(&version)
	switch err {
	case nil:
		if version != 0 {
			return fmt.Errorf("storage/pgx: incompatible db version: %v", version)
		}
	case pgx.ErrNoRows:
		if _, err = db.Exec("INSERT INTO metadata (version) VALUES ($1)", version); err != nil {
			return errors.Wrap(err, "storage/pgx: failed to set schema version")
		}
	default:
		return errors.Wrap(err, "storage/pgx: failed to query schema version")
	}

	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS store (digest BYTES PRIMARY KEY, expiration INT, blob BYTES NOT NULL, CONSTRAINT digest_length CHECK (length(digest) = 32))"); err != nil {
		return errors.Wrap(err, "storage/pgx: failed to create store table")
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS expiration_idx ON store (expiration)"); err != nil {
		return errors.Wrap(err, "storage/pgx: failed to create expiration index")
	}

	return nil
}
