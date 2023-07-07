package runtime

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/hashicorp/go-multierror"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
)

// TrustRoot is the consensus trust root verification scenario.
var TrustRoot scenario.Scenario = NewTrustRootImpl(
	"simple",
	NewKVTestClient().WithScenario(SimpleKeyValueEncScenario),
)

type TrustRootImpl struct {
	Scenario
}

func NewTrustRootImpl(name string, testClient TestClient) *TrustRootImpl {
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

func (sc *TrustRootImpl) registerRuntime(ctx context.Context, childEnv *env.Env, cli *cli.Helpers, rt *oasis.Runtime, validFrom beacon.EpochTime, nonce uint64) error {
	dsc := rt.ToRuntimeDescriptor()
	dsc.Deployments[0].ValidFrom = validFrom

	txPath := filepath.Join(childEnv.Dir(), fmt.Sprintf("register_runtime_%s.json", rt.ID()))
	if err := cli.Registry.GenerateRegisterRuntimeTx(childEnv.Dir(), dsc, nonce, txPath); err != nil {
		return fmt.Errorf("failed to generate register runtime tx: %w", err)
	}

	if err := cli.Consensus.SubmitTx(txPath); err != nil {
		return fmt.Errorf("failed to register runtime: %w", err)
	}

	return nil
}

func (sc *TrustRootImpl) updateKeyManagerPolicy(ctx context.Context, childEnv *env.Env, cli *cli.Helpers, nonce uint64) error {
	// Generate and update the new keymanager runtime's policy.
	kmPolicyPath := filepath.Join(childEnv.Dir(), "km_policy.cbor")
	kmPolicySig1Path := filepath.Join(childEnv.Dir(), "km_policy_sig1.pem")
	kmPolicySig2Path := filepath.Join(childEnv.Dir(), "km_policy_sig2.pem")
	kmPolicySig3Path := filepath.Join(childEnv.Dir(), "km_policy_sig3.pem")
	kmUpdateTxPath := filepath.Join(childEnv.Dir(), "km_gen_update.json")
	sc.Logger.Info("building KM SGX policy enclave policies map")
	enclavePolicies := make(map[sgx.EnclaveIdentity]*keymanager.EnclavePolicySGX)
	kmRt := sc.Net.Runtimes()[0]
	kmRtEncID := kmRt.GetEnclaveIdentity(0)
	var havePolicy bool
	if kmRtEncID != nil {
		enclavePolicies[*kmRtEncID] = &keymanager.EnclavePolicySGX{}
		enclavePolicies[*kmRtEncID].MayQuery = make(map[common.Namespace][]sgx.EnclaveIdentity)
		enclavePolicies[*kmRtEncID].MayReplicate = []sgx.EnclaveIdentity{}
		for _, rt := range sc.Net.Runtimes() {
			if rt.Kind() != registry.KindCompute {
				continue
			}
			if eid := rt.GetEnclaveIdentity(0); eid != nil {
				enclavePolicies[*kmRtEncID].MayQuery[rt.ID()] = []sgx.EnclaveIdentity{*eid}
				// This is set only in SGX mode.
				havePolicy = true
			}
		}
	}
	sc.Logger.Info("initing KM policy")
	if err := cli.Keymanager.InitPolicy(kmRt.ID(), 1, 0, enclavePolicies, kmPolicyPath); err != nil {
		return err
	}
	sc.Logger.Info("signing KM policy")
	if err := cli.Keymanager.SignPolicy("1", kmPolicyPath, kmPolicySig1Path); err != nil {
		return err
	}
	if err := cli.Keymanager.SignPolicy("2", kmPolicyPath, kmPolicySig2Path); err != nil {
		return err
	}
	if err := cli.Keymanager.SignPolicy("3", kmPolicyPath, kmPolicySig3Path); err != nil {
		return err
	}
	if havePolicy {
		// In SGX mode, we can update the policy as intended.
		sc.Logger.Info("updating KM policy")
		if err := cli.Keymanager.GenUpdate(nonce, kmPolicyPath, []string{kmPolicySig1Path, kmPolicySig2Path, kmPolicySig3Path}, kmUpdateTxPath); err != nil {
			return err
		}
		if err := cli.Consensus.SubmitTx(kmUpdateTxPath); err != nil {
			return fmt.Errorf("failed to update KM policy: %w", err)
		}
	}

	return nil
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
		if err = sc.registerRuntime(ctx, childEnv, cli, rt, epoch+2, nonce); err != nil {
			return err
		}
		nonce++
	}

	// Update the key manager policy.
	if err = sc.updateKeyManagerPolicy(ctx, childEnv, cli, nonce); err != nil {
		return err
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
		err2 := sc.PostRun(ctx, childEnv)
		err = multierror.Append(err, err2).ErrorOrNil()
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
	sc.Scenario.testClient = NewKVTestClient().WithSeed("seed2").WithScenario(NewTestClientScenario(queries))
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
