package e2e

import (
	"fmt"

	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
)

// TxSource is a network with the txsource program as a client.
var TxSource scenario.Scenario = &txSourceImpl{basicImpl{
	name:         "txsource",
	clientBinary: "txsource-wrapper.sh",
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

	cmd, err := startClient(childEnv, sc.net, sc.clientBinary, append([]string{
		"--genesis-path", sc.net.GenesisPath(),
		"--time-limit", "2m", // %%% low value for validation (:
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
