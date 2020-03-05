// +build gofuzz

package abci

import (
	"context"

	"github.com/tendermint/iavl"
	dbm "github.com/tendermint/tm-db"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	upgrade "github.com/oasislabs/oasis-core/go/upgrade/api"
)

func FuzzNewABCIMux(ctx context.Context) *abciMux {
	db := dbm.NewMemDB()
	deliverTxTree := iavl.NewMutableTree(db, 128)
	checkTxTree := iavl.NewMutableTree(db, 128)
	var ownTxSigner signature.PublicKey
	if err := ownTxSigner.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000061"); err != nil {
		db.Close()
		panic(err)
	}
	fakeMetricsCh := make(chan struct{})
	return &abciMux{
		logger: logging.GetLogger("abci-mux"),
		state: &applicationState{
			logger:          logging.GetLogger("abci-mux/state"),
			ctx:             ctx,
			db:              db,
			deliverTxTree:   deliverTxTree,
			checkTxTree:     checkTxTree,
			statePruner:     &nonePruner{},
			haltEpochHeight: 32,
			ownTxSigner:     ownTxSigner,
			metricsCloseCh:  fakeMetricsCh,
			metricsClosedCh: fakeMetricsCh,
		},
		appsByName:     make(map[string]Application),
		appsByMethod:   make(map[transaction.MethodName]Application),
		lastBeginBlock: -1,
	}
}

func FuzzMuxSetUpgrader(mux *abciMux, upgrader upgrade.Backend) {
	mux.upgrader = upgrader
}

func FuzzMuxSetEpochtime(mux *abciMux, epochTime epochtime.Backend) {
	mux.state.timeSource = epochTime
}

func FuzzMuxDoCleanup(mux *abciMux) {
	mux.doCleanup()
}

func FuzzMuxDoRegister(mux *abciMux, app Application) error {
	return mux.doRegister(app)
}
