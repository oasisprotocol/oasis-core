// +build gofuzz

package fuzz2

import (
	"context"
	"fmt"

	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/fill2"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	beaconapp "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/beacon"
	epochtimemockapp "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/epochtime_mock"
	keymanagerapp "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/keymanager"
	registryapp "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/registry"
	roothashapp "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/roothash"
	schedulerapp "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/scheduler"
	stakingapp "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/upgrade"
)

// Differences from fuzz:
// - fuzz2 is in memory
// - pruning is disabled in fuzz2
// - fuzz2 allows the fuzzer to send multiple transactions

type BlockMessages struct {
	BeginReq types.RequestBeginBlock
	TxReqs   []types.RequestDeliverTx
	EndReq   types.RequestEndBlock
}

type Messages struct {
	InitReq types.RequestInitChain
	Blocks  []BlockMessages
}

var _ epochtime.Backend = &simpleTime{}

type simpleTime struct {
	queryFactory *epochtimemockapp.QueryFactory
}

func (t *simpleTime) GetBaseEpoch(context.Context) (epochtime.EpochTime, error) {
	return 0, nil
}

func (t *simpleTime) GetEpoch(ctx context.Context, height int64) (epochtime.EpochTime, error) {
	q, err := t.queryFactory.QueryAt(ctx, height)
	if err != nil {
		return 0, fmt.Errorf("QueryAt %d: %w", height, err)
	}
	epoch, _, err := q.Epoch(ctx)
	if err != nil {
		return 0, fmt.Errorf("q Epoch: %w", err)
	}
	return epoch, nil
}

func (t *simpleTime) GetEpochBlock(context.Context, epochtime.EpochTime) (int64, error) {
	panic("not supported")
}

func (t *simpleTime) WatchEpochs() (<-chan epochtime.EpochTime, *pubsub.Subscription) {
	panic("not supported")
}

func (t *simpleTime) StateToGenesis(context.Context, int64) (*epochtime.Genesis, error) {
	panic("not supported")
}

func Fuzz(data []byte) int {
	var msgs Messages
	if err := fill2.Unmarshal(data, &msgs); err != nil {
		return 0
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mux := abci.FuzzNewABCIMux(ctx)
	defer abci.FuzzMuxDoCleanup(mux)
	abci.FuzzMuxSetUpgrader(mux, upgrade.NewDummyUpgradeManager())
	timeApp := epochtimemockapp.New()
	timeService := simpleTime{
		queryFactory: timeApp.QueryFactory().(*epochtimemockapp.QueryFactory),
	}
	if err := abci.FuzzMuxDoRegister(mux, timeApp); err != nil {
		panic(fmt.Errorf("register %s: %w", timeApp.Name(), err))
	}
	abci.FuzzMuxSetEpochtime(mux, &timeService)
	for _, app := range []abci.Application{
		beaconapp.New(),
		keymanagerapp.New(),
		registryapp.New(),
		stakingapp.New(),
		schedulerapp.New(),
		roothashapp.New(),
	} {
		if err := abci.FuzzMuxDoRegister(mux, app); err != nil {
			panic(fmt.Errorf("register %s: %w", app.Name(), err))
		}
	}

	mux.InitChain(msgs.InitReq)
	if mux.Failed {
		return 0
	}
	for _, block := range msgs.Blocks {
		mux.BeginBlock(block.BeginReq)
		if mux.Failed {
			return 0
		}
		for _, tx := range block.TxReqs {
			mux.DeliverTx(tx)
			if mux.Failed {
				return 0
			}
		}
		mux.EndBlock(block.EndReq)
		if mux.Failed {
			return 0
		}
		mux.Commit()
		if mux.Failed {
			return 0
		}
	}

	return 1
}
