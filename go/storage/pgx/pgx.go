// Package pgx implements a storage backend that uses the PostgreSQL
// wire protocol.
package pgx

import (
	"bytes"
	"fmt"
	"math"
	"strings"

	"github.com/cockroachdb/cockroach-go/crdb"
	"github.com/jackc/pgx"
	"github.com/jackc/pgx/pgtype"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/logging"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/storage/api"
)

const (
	// BackendName is the name of this implementation.
	BackendName = "pgx"

	cfgDatabaseURI    = "storage.pgx.database_uri"
	cfgMaxConnections = "storage.pgx.max_connections"

	stmtTagGet          = "get"
	stmtTagGetBatch     = "getBatch"
	stmtTagGetKeys      = "getKeys"
	stmtTagInsert       = "insert"
	stmtTagPurgeExpired = "purgeExpired"

	// The maximum INSERT/UPDATE size per single statement is limited
	// by `kv.raft.command.max_size`.
	maxUpdatePerStatement = 64 * 1024 * 1024

	// Longest expiration wins on the event of a conflict.  There's
	// no need to update the data because the storage is content addressed.
	clauseOnConflict = " ON CONFLICT (digest) DO UPDATE SET expiration = GREATEST(store.expiration, excluded.expiration)"
)

var (
	_ api.Backend          = (*pgxBackend)(nil)
	_ api.SweepableBackend = (*pgxBackend)(nil)

	_ pflag.Value = (*pgxConfig)(nil)

	flagDatabaseURI pgxConfig

	errElementTooLarge = fmt.Errorf("storage/pgx: element too large for insert")
)

type pgxBackend struct {
	logger *logging.Logger

	connPool *pgx.ConnPool
	sweeper  *api.Sweeper

	isCockroachDB bool
}

func (b *pgxBackend) Get(ctx context.Context, key api.Key) ([]byte, error) {
	epoch := b.sweeper.GetEpoch()
	if epoch == epochtime.EpochInvalid {
		return nil, api.ErrIncoherentTime
	}

	var value []byte

	err := b.connPool.QueryRowEx(ctx, stmtTagGet, nil, key[:], int64(epoch)).Scan(&value)
	switch err {
	case nil:
		if err = getValueOk(key, value); err != nil {
			return nil, err
		}
		return value, nil
	case pgx.ErrNoRows:
		return nil, api.ErrKeyNotFound
	default:
		return nil, errors.Wrap(err, "storage/pgx: failed Get() query")
	}
}

func (b *pgxBackend) GetBatch(ctx context.Context, keys []api.Key) ([][]byte, error) {
	epoch := b.sweeper.GetEpoch()
	if epoch == epochtime.EpochInvalid {
		return nil, api.ErrIncoherentTime
	}

	keyVec := make([][]byte, 0, len(keys))
	for _, v := range keys {
		keyVec = append(keyVec, v[:])
	}

	rows, err := b.connPool.QueryEx(ctx, stmtTagGetBatch, nil, int64(epoch), keyVec)
	if err != nil {
		return nil, errors.Wrap(err, "storage/pgx: failed GetBatch() query")
	}
	defer rows.Close()

	valueMap := make(map[api.Key][]byte)

	for rows.Next() {
		var rawKey, value []byte

		if err = rows.Scan(&rawKey, &value); err != nil {
			return nil, errors.Wrap(err, "storage/pgx: failed GetBatch() iterator")
		}

		var key api.Key
		copy(key[:], rawKey)

		if err = getValueOk(key, value); err != nil {
			return nil, err
		}

		valueMap[key] = value
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "storage/pgx: GetBatch() iterator error")
	}

	values := make([][]byte, 0, len(keys))
	for _, key := range keys {
		value, ok := valueMap[key]
		if !ok {
			return nil, api.ErrKeyNotFound
		}
		values = append(values, value)
	}

	return values, nil
}

func getValueOk(key api.Key, value []byte) error {
	keyCheck := api.HashStorageKey(value)
	if !bytes.Equal(key[:], keyCheck[:]) {
		return fmt.Errorf("storage/pgx: invariant violation H(value) != key")
	}
	return nil
}

func (b *pgxBackend) Insert(ctx context.Context, value []byte, expiration uint64) error {
	epoch := b.sweeper.GetEpoch()
	if epoch == epochtime.EpochInvalid {
		return api.ErrIncoherentTime
	}

	if api.KeySize+8+len(value) > maxUpdatePerStatement {
		return errElementTooLarge
	}

	args := insertArgsFromValue(&api.Value{Data: value, Expiration: expiration}, epoch)

	_, err := b.connPool.ExecEx(ctx, stmtTagInsert, nil, args...)
	if err != nil {
		return errors.Wrap(err, "storage/pgx: failed Insert() query")
	}

	return nil
}

func (b *pgxBackend) InsertBatch(ctx context.Context, values []api.Value) error {
	// Not having to use a transaction is significantly more lightweight.
	if len(values) == 1 {
		return b.Insert(ctx, values[0].Data, values[0].Expiration)
	}

	epoch := b.sweeper.GetEpoch()
	if epoch == epochtime.EpochInvalid {
		return api.ErrIncoherentTime
	}

	crTx, err := beginCrdbTx(b.connPool)
	if err != nil {
		return errors.Wrap(err, "storage/pgx: failed InsertBatch() Begin")
	}
	if err = crdb.ExecuteInTx(ctx, crTx, func() error {
		// CockroachDB claims to support the extended query protocol,
		// and batching and makes no claims about any limit to the
		// maximum batch size, so just blast away under the assumption
		// that there is no upper limit.
		//
		// See:
		//  * https://www.cockroachlabs.com/docs/stable/transactions.html
		//  * https://github.com/jackc/pgx/issues/374
		//
		// Note: If we're ok with partial writes being a possibility,
		// this could skip the transaction and the crdb overhead due
		// to the automatic retries.

		batch := crTx.Tx.BeginBatch()
		defer func() {
			if closeErr := batch.Close(); closeErr != nil {
				b.logger.Error("failed InsertBatch() pgx batch.Close()",
					"err", closeErr,
				)
			}
		}()

		var nrStmts int
		for i := 0; i < len(values); {
			// The CockroachDB documentation says that using multi-row
			// inserts is a good idea, with quite huge batch sizes.
			//
			// This aggregates each batch into huge INSERT statements,
			// the hard way, up to the maximum.

			var (
				args            []interface{}
				totalUpdateSize int
			)
			for j := i; j < len(values); j++ {
				updateSize := api.KeySize + 8 + len(values[j].Data)
				if totalUpdateSize+updateSize > maxUpdatePerStatement {
					break
				}
				totalUpdateSize += updateSize

				args = append(args, insertArgsFromValue(&values[j], epoch)...)
			}
			if len(args) == 0 {
				// There must be a huge element that won't be able to be
				// inserted.
				return errElementTooLarge
			}

			nrInserted := len(args) / 3
			i += nrInserted

			valuesVec := make([]string, 0, nrInserted)
			argOIDs := make([]pgtype.OID, 0, len(args))
			for j := 0; j < nrInserted; j++ {
				argOIDs = append(argOIDs, pgtype.ByteaOID)
				argOIDs = append(argOIDs, pgtype.Int8OID)
				argOIDs = append(argOIDs, pgtype.ByteaOID)
				k := j * 3
				valuesVec = append(valuesVec, fmt.Sprintf("($%d, $%d, $%d)", k+1, k+2, k+3))
			}
			stmt := "INSERT INTO store (digest, expiration, blob) VALUES " + strings.Join(valuesVec, ",") + clauseOnConflict // nolint: gosec

			batch.Queue(stmt, args, argOIDs, nil)
			nrStmts++
		}

		if err = batch.Send(ctx, nil); err != nil {
			return errors.Wrap(err, "storage/pgx: failed InsertBatch() pgx batch.Send()")
		}

		for i := 0; i < nrStmts; i++ {
			if _, err = batch.ExecResults(); err != nil {
				return errors.Wrap(err, "storage/pgx: failed InsertBatch() pgx batch.ExecResults()")
			}
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "storage/pgx: failed InsertBatch() tx")
	}

	return nil
}

func insertArgsFromValue(v *api.Value, epoch epochtime.EpochTime) []interface{} {
	key := api.HashStorageKey(v.Data)
	expiration := v.Expiration
	if expiration += uint64(epoch); expiration > math.MaxInt64 {
		// PostgreSQL only supports signed 64 bit integers.  The base
		// type should be redefined to be honest...
		expiration = math.MaxInt64
	}

	return []interface{}{key[:], expiration, v.Data}
}

func (b *pgxBackend) GetKeys(ctx context.Context) (<-chan *api.KeyInfo, error) {
	// Using this method isn't great because it will hold a connection
	// exclusively until it completes, which may be after a long while.
	rows, err := b.connPool.QueryEx(ctx, stmtTagGetKeys, nil)
	if err != nil {
		return nil, errors.Wrap(err, "storage/pgx: failed GetKeys() query")
	}

	ch := make(chan *api.KeyInfo)
	go func() {
		defer func() {
			rows.Close()
			close(ch)
		}()

		for rows.Next() {
			var (
				key        []byte
				expiration int64
			)

			if err := rows.Scan(&key, &expiration); err != nil {
				b.logger.Error("GetKeys(): Scan() failed",
					"err", err,
				)
				continue
			}

			ki := &api.KeyInfo{
				Expiration: epochtime.EpochTime(expiration),
			}
			copy(ki.Key[:], key)
			select {
			case ch <- ki:
			case <-ctx.Done():
				break
			}
		}
		if err := rows.Err(); err != nil {
			b.logger.Error("GetKeys(): rows iterator error",
				"err", err,
			)
		}
	}()

	return ch, nil
}

func (b *pgxBackend) Cleanup() {
	b.sweeper.Close()
	b.connPool.Close()
	b.connPool.Reset()
}

func (b *pgxBackend) Initialized() <-chan struct{} {
	return b.sweeper.Initialized()
}

func (b *pgxBackend) PurgeExpired(epoch epochtime.EpochTime) {
	if _, err := b.connPool.Exec(stmtTagPurgeExpired, epoch); err != nil {
		b.logger.Error("failed to purge expired entires",
			"err", err,
		)
	}
}

func (b *pgxBackend) detectCockroachDB() error {
	var version string
	if err := b.connPool.QueryRow("SELECT version()").Scan(&version); err != nil {
		return errors.Wrap(err, "storage/pgx: failed to query server version")
	}
	if !strings.HasPrefix(version, "CockroachDB") {
		b.logger.Debug("database does not appear to be CockroachDB")
		return nil
	}
	b.isCockroachDB = true

	return nil
}

func (b *pgxBackend) prepareStatements() error {

	stmtVec := []struct {
		tag, query string
	}{
		{stmtTagGet, "SELECT blob FROM store WHERE (digest = $1 AND expiration >= $2)"},
		{stmtTagGetBatch, "SELECT digest, blob FROM store WHERE (expiration >= $1 AND digest = ANY($2))"},
		{stmtTagGetKeys, "SELECT digest, expiration FROM store"},
		{stmtTagInsert, "INSERT INTO store (digest, expiration, blob) VALUES ($1, $2, $3)" + clauseOnConflict},
		{stmtTagPurgeExpired, "DELETE FROM store WHERE expiration < $1"},
	}
	for _, v := range stmtVec {
		if _, err := b.connPool.Prepare(v.tag, v.query); err != nil {
			return errors.Wrap(err, "storage/pgx: failed to prepare statement")
		}
	}

	return nil
}

// New constructs a new pgx backed storage Backend instance.
func New(timeSource epochtime.Backend) (api.Backend, error) {
	b := &pgxBackend{
		logger: logging.GetLogger("storage/pgx"),
	}

	// Ensure that sufficient configuration is provided.
	maxConnections := viper.GetInt(cfgMaxConnections)
	if flagDatabaseURI.cfg == nil {
		return nil, fmt.Errorf("storage/pgx: no database configured")
	}
	if maxConnections <= 0 {
		maxConnections = 1
	}

	connPoolCfg := pgx.ConnPoolConfig{
		ConnConfig:     *flagDatabaseURI.cfg,
		MaxConnections: maxConnections,
	}

	var err error
	b.connPool, err = pgx.NewConnPool(connPoolCfg)
	if err != nil {
		return nil, errors.Wrap(err, "storage/pgx: failed to connect to database")
	}

	var initOk bool
	defer func() {
		if !initOk {
			b.connPool.Close()
		}
	}()

	// Figure out if this is CockroachDB.
	if err = b.detectCockroachDB(); err != nil {
		return nil, err
	}
	if !b.isCockroachDB {
		return nil, fmt.Errorf("storage/pgx: database is not CockroachDB")
	}

	// Ensure the tables exist, and migrate as needed.
	if err = initSchemaV0(b.connPool); err != nil {
		return nil, err
	}

	// Initialize the prepared statements.
	if err = b.prepareStatements(); err != nil {
		return nil, err
	}

	b.sweeper = api.NewSweeper(b, timeSource)
	initOk = true

	return b, nil
}

type pgxConfig struct {
	cfg *pgx.ConnConfig

	uri string
}

func (c *pgxConfig) String() string {
	if c.uri == "" || c.cfg == nil {
		return "[unset]"
	}

	return c.uri
}

func (c *pgxConfig) Set(s string) error {
	cfg, err := pgx.ParseConnectionString(s)
	if err != nil {
		return err
	}

	c.cfg = &cfg
	c.uri = s

	return nil
}

func (c *pgxConfig) Type() string {
	return "[pgx URI/database DSN]"
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	cmd.Flags().Var(&flagDatabaseURI, cfgDatabaseURI, "pgx database URI")
	cmd.Flags().Int(cfgMaxConnections, 5, "pgx database maximum connections")

	for _, v := range []string{
		cfgDatabaseURI,
		cfgMaxConnections,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}
