package runtime

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/rust"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
)

const (
	cfgRuntimeSourceDir = "runtime.source_dir"
	cfgRuntimeTargetDir = "runtime.target_dir"

	trustRootRuntime = "simple-keyvalue"
)

// TrustRoot is the consensus trust root verification scenario.
var TrustRoot scenario.Scenario = newTrustRootImpl()

type trustRootImpl struct {
	runtimeImpl
}

func newTrustRootImpl() *trustRootImpl {
	sc := &trustRootImpl{
		runtimeImpl: *newRuntimeImpl("trust-root", BasicKVTestClient),
	}

	sc.Flags.String(cfgRuntimeSourceDir, "", "path to the runtime source base dir")
	sc.Flags.String(cfgRuntimeTargetDir, "", "path to the Cargo target dir (should be a parent of the runtime binary dir)")

	return sc
}

func (sc *trustRootImpl) Clone() scenario.Scenario {
	return &trustRootImpl{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (sc *trustRootImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
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
	for i := range f.ComputeWorkers {
		f.ComputeWorkers[i].NoAutoStart = true
	}
	for i := range f.Clients {
		f.Clients[i].NoAutoStart = true
	}

	return f, nil
}

func (sc *trustRootImpl) registerRuntime(ctx context.Context, childEnv *env.Env) error {
	// Nonce used for transactions (increase this by 1 after each transaction).
	var nonce uint64
	cli := cli.New(childEnv, sc.Net, sc.Logger)

	// Fetch current epoch.
	epoch, err := sc.Net.Controller().Beacon.GetEpoch(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to get current epoch: %w", err)
	}

	// Register a new keymanager runtime.
	kmRt := sc.Net.Runtimes()[0]
	rtDsc := kmRt.ToRuntimeDescriptor()
	rtDsc.Deployments[0].ValidFrom = epoch + 2
	kmTxPath := filepath.Join(childEnv.Dir(), "register_km_runtime.json")
	if err = cli.Registry.GenerateRegisterRuntimeTx(childEnv.Dir(), rtDsc, nonce, kmTxPath); err != nil {
		return fmt.Errorf("failed to generate register KM runtime tx: %w", err)
	}
	nonce++
	if err = cli.Consensus.SubmitTx(kmTxPath); err != nil {
		return fmt.Errorf("failed to register KM runtime: %w", err)
	}

	// Generate and update the new keymanager runtime's policy.
	kmPolicyPath := filepath.Join(childEnv.Dir(), "km_policy.cbor")
	kmPolicySig1Path := filepath.Join(childEnv.Dir(), "km_policy_sig1.pem")
	kmPolicySig2Path := filepath.Join(childEnv.Dir(), "km_policy_sig2.pem")
	kmPolicySig3Path := filepath.Join(childEnv.Dir(), "km_policy_sig3.pem")
	kmUpdateTxPath := filepath.Join(childEnv.Dir(), "km_gen_update.json")
	sc.Logger.Info("building KM SGX policy enclave policies map")
	enclavePolicies := make(map[sgx.EnclaveIdentity]*keymanager.EnclavePolicySGX)
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
	if err = cli.Keymanager.InitPolicy(kmRt.ID(), 1, enclavePolicies, kmPolicyPath); err != nil {
		return err
	}
	sc.Logger.Info("signing KM policy")
	if err = cli.Keymanager.SignPolicy("1", kmPolicyPath, kmPolicySig1Path); err != nil {
		return err
	}
	if err = cli.Keymanager.SignPolicy("2", kmPolicyPath, kmPolicySig2Path); err != nil {
		return err
	}
	if err = cli.Keymanager.SignPolicy("3", kmPolicyPath, kmPolicySig3Path); err != nil {
		return err
	}
	if havePolicy {
		// In SGX mode, we can update the policy as intended.
		sc.Logger.Info("updating KM policy")
		if err = cli.Keymanager.GenUpdate(nonce, kmPolicyPath, []string{kmPolicySig1Path, kmPolicySig2Path, kmPolicySig3Path}, kmUpdateTxPath); err != nil {
			return err
		}
		nonce++
		if err = cli.Consensus.SubmitTx(kmUpdateTxPath); err != nil {
			return fmt.Errorf("failed to update KM policy: %w", err)
		}
	}

	// Wait for key manager nodes to register.
	sc.Logger.Info("waiting for key manager nodes to initialize")
	for _, n := range sc.Net.Keymanagers() {
		if err = n.WaitReady(ctx); err != nil {
			return fmt.Errorf("failed to wait for a key manager node: %w", err)
		}
	}

	// Fetch current epoch.
	epoch, err = sc.Net.Controller().Beacon.GetEpoch(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to get current epoch: %w", err)
	}

	// Register a new compute runtime.
	compRt := sc.Net.Runtimes()[1]
	if err = compRt.RefreshRuntimeBundles(); err != nil {
		return fmt.Errorf("failed to refresh runtime bundles: %w", err)
	}
	compRtDesc := compRt.ToRuntimeDescriptor()
	compRtDesc.Deployments[0].ValidFrom = epoch + 2
	txPath := filepath.Join(childEnv.Dir(), "register_compute_runtime.json")
	if err = cli.Registry.GenerateRegisterRuntimeTx(childEnv.Dir(), compRtDesc, nonce, txPath); err != nil {
		return fmt.Errorf("failed to generate register compute runtime tx: %w", err)
	}
	if err = cli.Consensus.SubmitTx(txPath); err != nil {
		return fmt.Errorf("failed to register compute runtime: %w", err)
	}
	return nil
}

func (sc *trustRootImpl) Run(childEnv *env.Env) (err error) {
	// Determine the required directories for building the runtime with an embedded trust root.
	buildDir, _ := sc.Flags.GetString(cfgRuntimeSourceDir)
	targetDir, _ := sc.Flags.GetString(cfgRuntimeTargetDir)
	if len(buildDir) == 0 || len(targetDir) == 0 {
		return fmt.Errorf("runtime build dir and/or target dir not configured")
	}

	if err = sc.Net.Start(); err != nil {
		return err
	}

	// Let the network run for 10 blocks to select a suitable trust root.
	ctx := context.Background()
	blockCh, blockSub, err := sc.Net.Controller().Consensus.WatchBlocks(ctx)
	if err != nil {
		return err
	}
	defer blockSub.Close()

	sc.Logger.Info("waiting for some blocks")
	var blk *consensus.Block
	for {
		select {
		case blk = <-blockCh:
			if blk.Height < 10 {
				continue
			}
		case <-time.After(30 * time.Second):
			return fmt.Errorf("timed out waiting for blocks")
		}

		break
	}

	sc.Logger.Info("got some blocks, building runtime with given trust root",
		"trust_root_height", blk.Height,
		"trust_root_hash", blk.Hash.Hex(),
		"trust_root_runtime_id", runtimeID.String(),
	)

	// Build a new runtime with the given trust root embedded.
	sc.Logger.Info("building new runtime with embedded trust root")

	teeHardware, _ := sc.getTEEHardware()
	builder := rust.NewBuilder(childEnv, teeHardware, trustRootRuntime, filepath.Join(buildDir, trustRootRuntime), targetDir)
	builder.SetEnv("OASIS_TESTS_CONSENSUS_TRUST_HEIGHT", strconv.FormatInt(blk.Height, 10))
	builder.SetEnv("OASIS_TESTS_CONSENSUS_TRUST_HASH", blk.Hash.Hex())
	builder.SetEnv("OASIS_TESTS_CONSENSUS_TRUST_RUNTIME_ID", runtimeID.String())
	if err = builder.Build(); err != nil {
		return fmt.Errorf("failed to build runtime '%s' with trust root: %w", trustRootRuntime, err)
	}
	defer func() {
		// Make sure the binary is then rebuilt without the env vars set.
		sc.Logger.Info("rebuilding runtime without the embedded trust root")
		builder.ResetEnv()
		if buildErr := builder.Build(); buildErr != nil {
			err = fmt.Errorf("failed to build plain runtime '%s': %w (original error: %s)", trustRootRuntime, buildErr, err)
			return
		}
	}()

	// Now that the runtime is built, let's register it and start all the required workers.
	if err = sc.registerRuntime(ctx, childEnv); err != nil {
		return err
	}

	// Start the compute workers and client.
	sc.Logger.Info("starting clients and compute workers")
	for _, n := range sc.Net.Clients() {
		if err = n.Start(); err != nil {
			return fmt.Errorf("failed to start node: %w", err)
		}
	}
	for _, n := range sc.Net.ComputeWorkers() {
		if err = n.Start(); err != nil {
			return fmt.Errorf("failed to start node: %w", err)
		}
	}

	sc.Logger.Info("waiting for compute workers to become ready")
	for _, n := range sc.Net.ComputeWorkers() {
		if err = n.WaitReady(ctx); err != nil {
			return fmt.Errorf("failed to wait for a compute worker: %w", err)
		}
	}

	// Setup a client controller (as there is none due to the client node not being autostarted).
	ctrl, err := oasis.NewController(sc.Net.Clients()[0].SocketPath())
	if err != nil {
		return fmt.Errorf("failed to create client controller: %w", err)
	}
	sc.Net.SetClientController(ctrl)

	// Run the test client workload to ensure that blocks get processed correctly.
	if err = sc.startTestClientOnly(ctx, childEnv); err != nil {
		return err
	}
	if err = sc.waitTestClient(); err != nil {
		return err
	}

	sc.Logger.Info("testing query latest block")
	_, err = sc.submitKeyValueRuntimeGetQuery(
		ctx,
		runtimeID,
		"hello_key",
		roothash.RoundLatest,
	)
	if err != nil {
		return err
	}

	latestBlk, err := ctrl.Roothash.GetLatestBlock(ctx, &roothash.RuntimeRequest{RuntimeID: runtimeID, Height: consensus.HeightLatest})
	if err != nil {
		return err
	}
	round := latestBlk.Header.Round - 3
	sc.Logger.Info("testing query for past round", "round", round)
	_, err = sc.submitKeyValueRuntimeGetQuery(
		ctx,
		runtimeID,
		"hello_key",
		round,
	)
	if err != nil {
		return err
	}

	return nil
}
