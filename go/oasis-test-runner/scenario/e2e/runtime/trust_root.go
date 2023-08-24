package runtime

import (
	"context"
	"errors"
	"fmt"

	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
)

// TrustRoot is the consensus trust root verification scenario.
var TrustRoot scenario.Scenario = NewTrustRootImpl(
	"simple",
	NewTestClient().WithScenario(SimpleKeyValueEncScenario),
)

type TrustRootImpl struct {
	Scenario
}

func NewTrustRootImpl(name string, testClient *TestClient) *TrustRootImpl {
	fullName := "trust-root/" + name
	sc := &TrustRootImpl{
		Scenario: *NewScenario(fullName, testClient),
	}

	return sc
}

func (sc *TrustRootImpl) Clone() scenario.Scenario {
	return &TrustRootImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *TrustRootImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// Exclude all runtimes from genesis as we will register those dynamically since we need to
	// generate the correct enclave identity.
	for i := range f.Runtimes {
		f.Runtimes[i].ExcludeFromGenesis = true
	}

	// Make sure no nodes are started initially as we need to determine the trust root and build an
	// appropriate runtime with the trust root embedded.
	for i := range f.Keymanagers {
		f.Keymanagers[i].NoAutoStart = true
	}
	for i := range f.ComputeWorkers {
		f.ComputeWorkers[i].NoAutoStart = true
	}
	for i := range f.Clients {
		f.Clients[i].NoAutoStart = true
	}

	return f, nil
}

// PreRun starts the network, prepares a trust root, builds simple key/value and key manager
// runtimes, prepares runtime bundles, and runs the test client.
func (sc *TrustRootImpl) PreRun(ctx context.Context, childEnv *env.Env) (err error) {
	cli := cli.New(childEnv, sc.Net, sc.Logger)

	// Nonce used for transactions (increase this by 1 after each transaction).
	var nonce uint64

	// Start generating blocks.
	if err = sc.Net.Start(); err != nil {
		return err
	}
	if err = sc.Net.Controller().WaitNodesRegistered(ctx, len(sc.Net.Validators())); err != nil {
		return err
	}

	// Pick one block and use it as an embedded trust root.
	trustRoot, err := sc.TrustRoot(ctx)
	if err != nil {
		return err
	}

	// Build simple key/value and key manager runtimes.
	if err = sc.BuildAllRuntimes(ctx, childEnv, trustRoot); err != nil {
		return err
	}

	// Refresh the bundles. This needs to be done before setting the key manager policy,
	// to ensure enclave IDs are correct.
	for _, rt := range sc.Net.Runtimes() {
		if err = rt.RefreshRuntimeBundles(); err != nil {
			return fmt.Errorf("failed to refresh runtime bundles: %w", err)
		}
	}

	// Fetch current epoch.
	epoch, err := sc.Net.Controller().Beacon.GetEpoch(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to get current epoch: %w", err)
	}

	// Register the runtimes.
	for _, rt := range sc.Net.Runtimes() {
		rtDsc := rt.ToRuntimeDescriptor()
		rtDsc.Deployments[0].ValidFrom = epoch + 2
		if err = sc.RegisterRuntime(ctx, childEnv, cli, rtDsc, nonce); err != nil {
			return err
		}
		nonce++
	}

	// Update the key manager policy.
	policies, err := sc.BuildEnclavePolicies(childEnv)
	if err != nil {
		return err
	}
	switch policies {
	case nil:
		sc.Logger.Info("no SGX runtimes, skipping policy update")
	default:
		if err = sc.ApplyKeyManagerPolicy(ctx, childEnv, cli, 0, policies, nonce); err != nil {
			return fmt.Errorf("updating policies: %w", err)
		}
		nonce++ // nolint: ineffassign
	}

	// Start all the required workers.
	if err = sc.startClientComputeAndKeyManagerNodes(ctx, childEnv); err != nil {
		return err
	}

	// Run the test client workload to ensure that blocks get processed correctly.
	return sc.RunTestClientAndCheckLogs(ctx, childEnv)
}

// PostRun re-builds simple key/value and key manager runtimes.
func (sc *TrustRootImpl) PostRun(ctx context.Context, childEnv *env.Env) error {
	// In the end, always rebuild all runtimes as we are changing binaries in one of the steps.
	return sc.BuildAllRuntimes(ctx, childEnv, nil)
}

func (sc *TrustRootImpl) Run(ctx context.Context, childEnv *env.Env) (err error) {
	if err = sc.PreRun(ctx, childEnv); err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, sc.PostRun(ctx, childEnv))
	}()

	sc.Logger.Info("testing query latest block")
	_, err = sc.submitKeyValueRuntimeGetQuery(
		ctx,
		KeyValueRuntimeID,
		"hello_key",
		roothash.RoundLatest,
	)
	if err != nil {
		return err
	}

	latestBlk, err := sc.Net.ClientController().Roothash.GetLatestBlock(ctx, &roothash.RuntimeRequest{RuntimeID: KeyValueRuntimeID, Height: consensus.HeightLatest})
	if err != nil {
		return err
	}
	round := latestBlk.Header.Round - 3
	sc.Logger.Info("testing query for past round", "round", round)
	_, err = sc.submitKeyValueRuntimeGetQuery(
		ctx,
		KeyValueRuntimeID,
		"hello_key",
		round,
	)
	if err != nil {
		return err
	}

	// Run the test client again to verify that queries work correctly immediately after
	// the transactions have been published.
	queries := make([]interface{}, 0)
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("my_key_%d", i)
		value := fmt.Sprintf("my_value_%d", i)

		// Use non-encrypted transactions, as queries don't support decryption.
		queries = append(queries,
			InsertKeyValueTx{key, value, "", false, 0},
			KeyValueQuery{key, value, roothash.RoundLatest},
		)
	}

	sc.Logger.Info("starting a second test client to check if queries for the last round work")
	sc.Scenario.TestClient = NewTestClient().WithSeed("seed2").WithScenario(NewTestClientScenario(queries))
	return sc.RunTestClientAndCheckLogs(ctx, childEnv)
}

func (sc *TrustRootImpl) startClientComputeAndKeyManagerNodes(ctx context.Context, childEnv *env.Env) error {
	// Start client, compute workers and key manager nodes as they are not auto-started.
	sc.Logger.Info("starting clients, compute workers and key managers")
	for _, n := range sc.Net.Clients() {
		if err := n.Start(); err != nil {
			return fmt.Errorf("failed to start node: %w", err)
		}
	}
	for _, n := range sc.Net.ComputeWorkers() {
		if err := n.Start(); err != nil {
			return fmt.Errorf("failed to start node: %w", err)
		}
	}
	for _, n := range sc.Net.Keymanagers() {
		if err := n.Start(); err != nil {
			return fmt.Errorf("failed to start node: %w", err)
		}
	}

	sc.Logger.Info("waiting for key manager nodes to become ready")
	for _, n := range sc.Net.Keymanagers() {
		if err := n.WaitReady(ctx); err != nil {
			return fmt.Errorf("failed to wait for a key manager node: %w", err)
		}
	}

	sc.Logger.Info("waiting for compute workers to become ready")
	for _, n := range sc.Net.ComputeWorkers() {
		if err := n.WaitReady(ctx); err != nil {
			return fmt.Errorf("failed to wait for a compute worker: %w", err)
		}
	}

	sc.Logger.Info("waiting for client nodes to become ready")
	for _, n := range sc.Net.Clients() {
		if err := n.WaitReady(ctx); err != nil {
			return fmt.Errorf("failed to wait for a client node: %w", err)
		}
	}

	// Setup a client controller as there is none due to the client node not
	// being auto-started.
	ctrl, err := oasis.NewController(sc.Net.Clients()[0].SocketPath())
	if err != nil {
		return fmt.Errorf("failed to create client controller: %w", err)
	}
	sc.Net.SetClientController(ctrl)

	return nil
}
