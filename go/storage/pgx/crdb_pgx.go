package pgx

import (
	"context"
	"database/sql"
	"database/sql/driver"

	"github.com/cockroachdb/cockroach-go/crdb"
	"github.com/jackc/pgx"
)

var _ crdb.Tx = (*pgxCrdbTx)(nil)

type beginAble interface {
	Begin() (*pgx.Tx, error)
}

type pgxCrdbTx struct {
	*pgx.Tx
}

func (tx *pgxCrdbTx) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	tag, err := tx.Tx.ExecEx(ctx, query, nil, args...)
	return driver.RowsAffected(tag.RowsAffected()), err
}

func (tx *pgxCrdbTx) Commit() error {
	return tx.Tx.Commit()
}

func (tx *pgxCrdbTx) Rollback() error {
	return tx.Tx.Rollback()
}

func beginCrdbTx(conn beginAble) (*pgxCrdbTx, error) {
	baseTx, err := conn.Begin()
	if err != nil {
		return nil, err
	}
	return &pgxCrdbTx{Tx: baseTx}, nil
}
