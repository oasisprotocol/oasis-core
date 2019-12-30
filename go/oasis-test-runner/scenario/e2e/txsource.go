package e2e

import (
	"fmt"
	"time"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/debug/txsource"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/debug/txsource/workload"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
)

// TxSource is a network with the txsource program as a client.
var TxSource scenario.Scenario = &txSourceImpl{basicImpl{
	name: "txsource",
}}

type txSourceImpl struct {
	basicImpl
}

func (sc *txSourceImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.basicImpl.Fixture()
	if err != nil {
		return nil, err
	}
	f.Network.StakingGenesis = "tests/fixture-data/txsource/staking-genesis.json"

	return f, nil
}

func (sc *txSourceImpl) Init(childEnv *env.Env, net *oasis.Network) error {
	sc.net = net
	return nil
}

func (sc *txSourceImpl) Run(childEnv *env.Env) error {
	if err := sc.net.Start(); err != nil {
		return fmt.Errorf("scenario net Start: %w", err)
	}

	logFmt := logging.FmtJSON
	logLevel := logging.LevelDebug
	cmd, err := startClient(childEnv, sc.net, "scripts/txsource-wrapper.sh", append([]string{
		"--",
		"--" + common.CfgDebugAllowTestKeys,
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + flags.CfgDebugTestEntity,
		"--log.format", logFmt.String(),
		"--log.level", logLevel.String(),
		"--" + flags.CfgGenesisFile, sc.net.GenesisPath(),
		"--" + txsource.CfgWorkload, workload.NameTransfer,
		"--" + txsource.CfgTimeLimit, (2 * time.Minute).String(), // %%% low value for validation (:
	}, sc.clientArgs...))
	if err != nil {
		return fmt.Errorf("startClient: %w", err)
	}

	clientErrCh := make(chan error)
	go func() {
		clientErrCh <- cmd.Wait()
	}()

	return sc.wait(childEnv, cmd, clientErrCh)
}
