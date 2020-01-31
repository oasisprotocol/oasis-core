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

const (
	timeLimitShort = time.Minute
	timeLimitLong  = 43 * time.Minute
)

// TxSourceTransferShort uses the transfer workload for a short time.
var TxSourceTransferShort scenario.Scenario = &txSourceImpl{
	basicImpl: *newBasicImpl("txsource-transfer-short", "", nil),
	workload:  workload.NameTransfer,
	timeLimit: timeLimitShort,
}

// TxSourceTransfer uses the transfer workload.
var TxSourceTransfer scenario.Scenario = &txSourceImpl{
	basicImpl: *newBasicImpl("txsource-transfer", "", nil),
	workload:  workload.NameTransfer,
	timeLimit: timeLimitLong,
}

type txSourceImpl struct {
	basicImpl

	workload  string
	timeLimit time.Duration
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

	// Wait for all nodes to be synced before we proceed.
	if err := sc.waitNodesSynced(); err != nil {
		return err
	}

	logFmt := logging.FmtJSON
	logLevel := logging.LevelDebug
	cmd, err := startClient(childEnv, sc.net, "scripts/txsource-wrapper.sh", append([]string{
		"--node-binary", sc.net.Config().NodeBinary,
		"--",
		"--" + common.CfgDebugAllowTestKeys,
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + flags.CfgDebugTestEntity,
		"--log.format", logFmt.String(),
		"--log.level", logLevel.String(),
		"--" + flags.CfgGenesisFile, sc.net.GenesisPath(),
		"--" + txsource.CfgWorkload, sc.workload,
		"--" + txsource.CfgTimeLimit, sc.timeLimit.String(),
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
