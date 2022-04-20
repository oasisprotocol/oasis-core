package e2e

import (
	"context"
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/control/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// SeedAPI is the scenario where seed node control and consensus APIs are tested.
var SeedAPI scenario.Scenario = &seedAPI{
	E2E: *NewE2E("seed-api"),
}

type seedAPI struct {
	E2E
}

func (sc *seedAPI) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.E2E.Fixture()
	if err != nil {
		return nil, err
	}

	// Add a client which will connect to the seed.
	f.Clients = append(f.Clients, oasis.ClientFixture{})

	f.Network.SetInsecureBeacon()

	return f, nil
}

func (sc *seedAPI) Clone() scenario.Scenario {
	return &seedAPI{
		E2E: sc.E2E.Clone(),
	}
}

func (sc *seedAPI) Run(childEnv *env.Env) error { // nolint: gocyclo
	if err := sc.Net.Start(); err != nil {
		return fmt.Errorf("net Start: %w", err)
	}

	ctx := context.Background()

	sc.Logger.Info("waiting for network to come up")
	if err := sc.Net.Controller().WaitNodesRegistered(ctx, 3); err != nil {
		return fmt.Errorf("WaitNodesRegistered: %w", err)
	}

	seedCtrl, err := oasis.NewController(sc.Net.Seeds()[0].SocketPath())
	if err != nil {
		return err
	}

	sc.Logger.Info("testing IsSynced")
	isSynced, err := seedCtrl.IsSynced(ctx)
	if err != nil {
		return err
	}
	if !isSynced {
		return fmt.Errorf("seed reports as not synced")
	}

	sc.Logger.Info("testing IsReady")
	isReady, err := seedCtrl.IsReady(ctx)
	if err != nil {
		return err
	}
	if isReady {
		return fmt.Errorf("seed reports as ready to accept runtime work")
	}

	sc.Logger.Info("testing GetStatus")
	status, err := seedCtrl.GetStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to get status for node: %w", err)
	}
	if status.Consensus.Status != consensusAPI.StatusStateReady {
		return fmt.Errorf("seed node consensus status should be '%s', got: '%s'", consensusAPI.StatusStateReady, status.Consensus.Status)
	}
	if status.Consensus.LatestHeight != int64(0) {
		return fmt.Errorf("seed node latest height should be 0, got: %d", status.Consensus.LatestHeight)
	}
	if status.Consensus.IsValidator {
		return fmt.Errorf("seed node reports itself to be a validator")
	}
	if status.Consensus.Features.Has(consensusAPI.FeatureServices) {
		return fmt.Errorf("seed node reports feature services")
	}
	if len(status.Runtimes) != 0 {
		return fmt.Errorf("seed node reports configured runtimes")
	}
	rs := api.RegistrationStatus{}
	if status.Registration != rs {
		return fmt.Errorf("seed reports as registered")
	}
	if len(status.Consensus.NodePeers) == 0 {
		return fmt.Errorf("seed should be conencted at least to the client-0")
	}
	if p := status.PendingUpgrades; len(p) != 0 {
		return fmt.Errorf("unexpected pending upgrades: %v", p)
	}

	sc.Logger.Info("testing SetEpoch")
	if err = seedCtrl.SetEpoch(ctx, beacon.EpochTime(0)); err == nil {
		return fmt.Errorf("seed node SetEpoch should fail")
	}

	sc.Logger.Info("testing GetGenesisDocument")
	doc, err := seedCtrl.Consensus.GetGenesisDocument(ctx)
	if err != nil {
		return fmt.Errorf("seed node GetGenesisDocument should work")
	}
	if doc == nil {
		return fmt.Errorf("seed node GetGenesisDocument should not be nil")
	}

	sc.Logger.Info("testing SubmitTx")
	err = seedCtrl.Consensus.SubmitTx(ctx, &transaction.SignedTransaction{})
	if err != consensusAPI.ErrUnsupported {
		return fmt.Errorf("seed node SubmitTx should fail with unsupported")
	}

	sc.Logger.Info("testing SubmitTxNoWait")
	err = seedCtrl.Consensus.SubmitTxNoWait(ctx, &transaction.SignedTransaction{})
	if err != consensusAPI.ErrUnsupported {
		return fmt.Errorf("seed node SubmitTxNoWait should fail with unsupported")
	}

	sc.Logger.Info("testing SubmitEvidence")
	err = seedCtrl.Consensus.SubmitEvidence(ctx, &consensusAPI.Evidence{})
	if err != consensusAPI.ErrUnsupported {
		return fmt.Errorf("seed node SubmitEvidence should fail with unsupported")
	}

	sc.Logger.Info("testing StateToGenesis")
	_, err = seedCtrl.Consensus.StateToGenesis(ctx, 0)
	if err != consensusAPI.ErrUnsupported {
		return fmt.Errorf("seed node StateToGenesis should fail with unsupported")
	}

	sc.Logger.Info("testing EstimateGas")
	_, err = seedCtrl.Consensus.EstimateGas(ctx, &consensusAPI.EstimateGasRequest{})
	if err != consensusAPI.ErrUnsupported {
		return fmt.Errorf("seed node EstimateGas should fail with unsupported")
	}

	sc.Logger.Info("testing GetBlock")
	_, err = seedCtrl.Consensus.GetBlock(ctx, consensusAPI.HeightLatest)
	if err != consensusAPI.ErrUnsupported {
		return fmt.Errorf("seed node GetBlock should fail with unsupported")
	}

	sc.Logger.Info("testing GetTransactions")
	_, err = seedCtrl.Consensus.GetTransactions(ctx, consensusAPI.HeightLatest)
	if err != consensusAPI.ErrUnsupported {
		return fmt.Errorf("seed node GetTransactions should fail with unsupported")
	}

	sc.Logger.Info("testing GetTransactionsWithResults")
	_, err = seedCtrl.Consensus.GetTransactionsWithResults(ctx, consensusAPI.HeightLatest)
	if err != consensusAPI.ErrUnsupported {
		return fmt.Errorf("seed node GetTransactionsWithResults should fail with unsupported")
	}

	sc.Logger.Info("testing GetUnconfirmedTransactions")
	_, err = seedCtrl.Consensus.GetUnconfirmedTransactions(ctx)
	if err != consensusAPI.ErrUnsupported {
		return fmt.Errorf("seed node GetUnconfirmedTransactions should fail with unsupported")
	}

	sc.Logger.Info("testing GetSignerNonce")
	_, err = seedCtrl.Consensus.GetSignerNonce(ctx, &consensusAPI.GetSignerNonceRequest{})
	if err != consensusAPI.ErrUnsupported {
		return fmt.Errorf("seed node GetSignerNonce should fail with unsupported")
	}

	sc.Logger.Info("testing GetLightBlock")
	_, err = seedCtrl.Consensus.GetLightBlock(ctx, consensusAPI.HeightLatest)
	if err != consensusAPI.ErrUnsupported {
		return fmt.Errorf("seed node GetLightBlock should fail with unsupported")
	}

	sc.Logger.Info("testing GetParameters")
	_, err = seedCtrl.Consensus.GetParameters(ctx, consensusAPI.HeightLatest)
	if err != consensusAPI.ErrUnsupported {
		return fmt.Errorf("seed node GetParameters should fail with unsupported")
	}

	sc.Logger.Info("testing RequestShutdown")
	if err := seedCtrl.RequestShutdown(ctx, true); err != nil {
		return fmt.Errorf("seed node request shutdown error: %w", err)
	}

	return nil
}
