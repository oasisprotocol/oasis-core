package full

import (
	"context"
	"fmt"

	tmconfig "github.com/tendermint/tendermint/config"
	tmkeymigrate "github.com/tendermint/tendermint/scripts/keymigrate"
	tmscmigrate "github.com/tendermint/tendermint/scripts/scmigrate"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
)

func migrateTendermintDB(ctx context.Context, logger *logging.Logger, tenderConfig *tmconfig.Config, dbProvider tmconfig.DBProvider) error {
	for _, dbCtx := range []string{"blockstore", "state", "peerstore", "tx_index", "evidence", "light"} {
		db, derr := dbProvider(&tmconfig.DBContext{ID: dbCtx, Config: tenderConfig})
		if derr != nil {
			logger.Error("failed to obtain database provider for given tendermint database",
				"err", derr,
				"db", dbCtx,
			)
			return derr
		}

		logger.Info("performing tendermint database migration",
			"db", dbCtx,
		)
		derr = tmkeymigrate.Migrate(ctx, db)
		if derr != nil {
			logger.Error("tendermint database migration failed",
				"db", dbCtx,
				"err", derr,
			)
			return fmt.Errorf("tendermint: state database migration failed: %w", derr)
		}
		logger.Info("tendermint database migration completed",
			"db", dbCtx,
		)

		if dbCtx == "blockstore" {
			logger.Info("performing tendermint seen commit migration")
			derr = tmscmigrate.Migrate(ctx, db)
			if derr != nil {
				logger.Info("tendermint seen commit migration failed",
					"err", derr,
				)
				return fmt.Errorf("tendermint: seen commit migration failed: %w", derr)
			}
			logger.Info("tendermint seen commit migration completed")
		}

		db.Close()
	}

	return nil
}
