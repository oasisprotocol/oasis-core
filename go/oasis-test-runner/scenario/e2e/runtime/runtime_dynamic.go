package runtime

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// RuntimeDynamic is the dynamic runtime registration scenario.
var RuntimeDynamic scenario.Scenario = newRuntimeDynamicImpl()

type runtimeDynamicImpl struct {
	runtimeImpl

	epoch beacon.EpochTime
}

func newRuntimeDynamicImpl() scenario.Scenario {
	return &runtimeDynamicImpl{
		runtimeImpl: *newRuntimeImpl("runtime-dynamic", nil),
	}
}

func (sc *runtimeDynamicImpl) Clone() scenario.Scenario {
	return &runtimeDynamicImpl{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
		epoch:       sc.epoch,
	}
}

func (sc *runtimeDynamicImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Allocate stake and set runtime thresholds.
	f.Network.StakingGenesis = &staking.Genesis{
		Parameters: staking.ConsensusParameters{
			Thresholds: map[staking.ThresholdKind]quantity.Quantity{
				staking.KindEntity:            *quantity.NewFromUint64(0),
				staking.KindNodeValidator:     *quantity.NewFromUint64(0),
				staking.KindNodeCompute:       *quantity.NewFromUint64(0),
				staking.KindNodeKeyManager:    *quantity.NewFromUint64(0),
				staking.KindRuntimeCompute:    *quantity.NewFromUint64(1000),
				staking.KindRuntimeKeyManager: *quantity.NewFromUint64(1000),
			},
		},
	}
	// Avoid unexpected blocks.
	f.Network.SetMockEpoch()
	// Exclude all runtimes from genesis as we will register those dynamically.
	for i := range f.Runtimes {
		f.Runtimes[i].ExcludeFromGenesis = true
	}
	// Test with a non-zero round.
	f.Runtimes[1].GenesisRound = 42

	return f, nil
}

func (sc *runtimeDynamicImpl) epochTransition(ctx context.Context) error {
	sc.epoch++

	sc.Logger.Info("triggering epoch transition",
		"epoch", sc.epoch,
	)
	if err := sc.Net.Controller().SetEpoch(ctx, sc.epoch); err != nil {
		return fmt.Errorf("failed to set epoch: %w", err)
	}
	sc.Logger.Info("epoch transition done")
	return nil
}

func (sc *runtimeDynamicImpl) Run(childEnv *env.Env) error { // nolint: gocyclo
	var rtNonce uint64
	if err := sc.Net.Start(); err != nil {
		return err
	}

	ctx := context.Background()
	cli := cli.New(childEnv, sc.Net, sc.Logger)

	// Wait for all nodes to be synced before we proceed.
	if err := sc.waitNodesSynced(); err != nil {
		return err
	}

	// Wait for validator nodes to register.
	sc.Logger.Info("waiting for validator nodes to initialize",
		"num_validators", len(sc.Net.Validators()),
	)
	for _, n := range sc.Net.Validators() {
		if err := n.WaitReady(ctx); err != nil {
			return fmt.Errorf("failed to wait for a validator: %w", err)
		}
	}

	// Perform an initial epoch transition to make sure that the nodes can handle it even though
	// there are no runtimes registered yet.
	if err := sc.epochTransition(ctx); err != nil {
		return err
	}

	// Nonce used for transactions (increase this by 1 after each transaction).
	var nonce uint64

	// Fetch current epoch.
	epoch, err := sc.Net.Controller().Beacon.GetEpoch(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to get current epoch: %w", err)
	}

	// Register a new keymanager runtime.
	kmRt := sc.Net.Runtimes()[0]
	rtDsc := kmRt.ToRuntimeDescriptor()
	rtDsc.Deployments[0].ValidFrom = epoch + 1
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
	} else {
		// In non-SGX mode, the policy update fails with a policy checksum
		// mismatch (the non-SGX KM returns an empty policy), so we need to
		// do an epoch transition instead (to complete the KM runtime
		// registration).
		if err = sc.epochTransition(ctx); err != nil {
			return err
		}
	}

	// Wait for key manager nodes to register, then make another epoch transition.
	sc.Logger.Info("waiting for key manager nodes to initialize",
		"num_keymanagers", len(sc.Net.Keymanagers()),
	)
	for _, n := range sc.Net.Keymanagers() {
		if err = n.WaitReady(ctx); err != nil {
			return fmt.Errorf("failed to wait for a validator: %w", err)
		}
	}
	if err = sc.epochTransition(ctx); err != nil {
		return err
	}

	// Fetch current epoch.
	epoch, err = sc.Net.Controller().Beacon.GetEpoch(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to get current epoch: %w", err)
	}

	// Register a new compute runtime.
	compRt := sc.Net.Runtimes()[1]
	compRtDesc := compRt.ToRuntimeDescriptor()
	compRtDesc.Deployments[0].ValidFrom = epoch + 1
	txPath := filepath.Join(childEnv.Dir(), "register_compute_runtime.json")
	if err = cli.Registry.GenerateRegisterRuntimeTx(childEnv.Dir(), compRtDesc, nonce, txPath); err != nil {
		return fmt.Errorf("failed to generate register compute runtime tx: %w", err)
	}
	nonce++
	if err = cli.Consensus.SubmitTx(txPath); err != nil {
		return fmt.Errorf("failed to register compute runtime: %w", err)
	}

	// Wait for compute workers to become ready.
	sc.Logger.Info("waiting for compute workers to initialize",
		"num_compute_workers", len(sc.Net.ComputeWorkers()),
	)
	for _, n := range sc.Net.ComputeWorkers() {
		if err = n.WaitReady(ctx); err != nil {
			return fmt.Errorf("failed to wait for a compute worker: %w", err)
		}
	}

	// Perform an epoch transition to make sure all nodes are eligible. They may not be eligible
	// if they have registered after the beacon commit phase.
	if err = sc.epochTransition(ctx); err != nil {
		return err
	}

	for i := 0; i < 5; i++ {
		// Perform another epoch transition to elect compute runtime committees.
		if err = sc.epochTransition(ctx); err != nil {
			return err
		}

		// Wait a bit after epoch transitions.
		time.Sleep(1 * time.Second)

		// Submit a runtime transaction.
		sc.Logger.Info("submitting transaction to runtime",
			"seq", i,
		)
		if _, err = sc.submitKeyValueRuntimeInsertTx(ctx, runtimeID, "hello", fmt.Sprintf("world %d", i), rtNonce); err != nil {
			return err
		}
		rtNonce++
	}

	// Stop all runtime nodes, so they will not re-register, causing the nodes to expire.
	sc.Logger.Info("stopping compute nodes")
	for _, n := range sc.Net.ComputeWorkers() {
		if err = n.Stop(); err != nil {
			return fmt.Errorf("failed to stop node: %w", err)
		}
	}

	// Epoch transitions so nodes expire.
	sc.Logger.Info("performing epoch transitions so nodes expire")
	for i := 0; i < 3; i++ {
		if err = sc.epochTransition(ctx); err != nil {
			return err
		}

		// Wait a bit between epoch transitions.
		time.Sleep(1 * time.Second)
	}

	// Ensure that runtime got suspended.
	sc.Logger.Info("checking that runtime got suspended")
	_, err = sc.Net.Controller().Registry.GetRuntime(ctx, &registry.GetRuntimeQuery{
		Height: consensus.HeightLatest,
		ID:     compRtDesc.ID,
	})
	switch err {
	case nil:
		return fmt.Errorf("runtime should be suspended but it is not")
	case registry.ErrNoSuchRuntime:
		// Runtime is suspended.
	default:
		return fmt.Errorf("unexpected error while fetching runtime: %w", err)
	}

	// Start runtime nodes, make sure they register.
	sc.Logger.Info("starting compute nodes")
	for _, n := range sc.Net.ComputeWorkers() {
		if err = n.Start(); err != nil {
			return fmt.Errorf("failed to start node: %w", err)
		}
	}

	sc.Logger.Info("waiting for compute workers to initialize",
		"num_compute_workers", len(sc.Net.ComputeWorkers()),
	)
	for _, n := range sc.Net.ComputeWorkers() {
		if err = n.WaitReady(ctx); err != nil {
			return fmt.Errorf("failed to wait for a compute worker: %w", err)
		}
	}

	// Perform an epoch transition to make sure all nodes are eligible. They may not be eligible
	// if they have registered after the beacon commit phase.
	if err = sc.epochTransition(ctx); err != nil {
		return err
	}

	// Epoch transition.
	if err = sc.epochTransition(ctx); err != nil {
		return err
	}

	// Submit a runtime transaction to check whether the runtimes got resumed.
	sc.Logger.Info("submitting transaction to runtime")
	if _, err = sc.submitKeyValueRuntimeInsertTx(ctx, runtimeID, "hello", "final world", rtNonce); err != nil {
		return err
	}
	rtNonce++

	// Now reclaim all stake from the debug entity which owns the runtime.
	sc.Logger.Info("reclaiming stake from entity which owns the runtime")
	entSigner := sc.Net.Entities()[0].Signer()
	entAddr := staking.NewAddress(entSigner.Public())
	var oneShare quantity.Quantity
	_ = oneShare.FromUint64(1)
	tx := staking.NewReclaimEscrowTx(nonce, &transaction.Fee{Gas: 10000}, &staking.ReclaimEscrow{
		Account: entAddr,
		Shares:  oneShare,
	})
	nonce++
	sigTx, err := transaction.Sign(entSigner, tx)
	if err != nil {
		return fmt.Errorf("failed to sign reclaim: %w", err)
	}
	if err = sc.Net.Controller().Consensus.SubmitTx(ctx, sigTx); err != nil {
		return fmt.Errorf("failed to reclaim stake: %w", err)
	}

	// Watch node registrations so we know when node re-register. We want to ensure that node
	// re-registrations will not cause the runtimes to be resumed.
	nodeCh, nodeSub, err := sc.Net.Controller().Registry.WatchNodes(ctx)
	if err != nil {
		return fmt.Errorf("failed to watch nodes: %w", err)
	}
	defer nodeSub.Close()

	// Epoch transition to make the debonding period expire.
	if err = sc.epochTransition(ctx); err != nil {
		return err
	}

	// Wait a bit to give the nodes time to renew their registration.
	waitForNodeUpdates := func() error {
		sc.Logger.Info("waiting for node re-registrations")
		nodeUpdates := make(map[signature.PublicKey]bool)
		for {
			select {
			case ev := <-nodeCh:
				if ev.IsRegistration {
					nodeUpdates[ev.Node.ID] = true
					if len(nodeUpdates) == sc.Net.NumRegisterNodes() {
						return nil
					}
				}
			case <-time.After(10 * time.Second):
				return fmt.Errorf("failed to wait for all nodes to re-register")
			}
		}
	}
	if err = waitForNodeUpdates(); err != nil {
		return err
	}

	// Ensure that runtimes got suspended.
	ensureRuntimesSuspended := func(suspended bool) error {
		sc.Logger.Info("checking that runtimes got (un)suspended")
		for _, rt := range sc.Net.Runtimes() {
			_, err = sc.Net.Controller().Registry.GetRuntime(ctx, &registry.GetRuntimeQuery{
				Height: consensus.HeightLatest,
				ID:     rt.ID(),
			})
			switch err {
			case nil:
				if suspended {
					return fmt.Errorf("runtime %s should be suspended but it is not", rt.ID())
				}
			case registry.ErrNoSuchRuntime:
				// Runtime is suspended.
				if !suspended {
					return fmt.Errorf("runtime %s should NOT be suspended but it is", rt.ID())
				}
			default:
				return fmt.Errorf("unexpected error while fetching runtime %s: %w", rt.ID(), err)
			}
		}
		return nil
	}
	if err = ensureRuntimesSuspended(true); err != nil {
		return err
	}

	// Restart nodes to test that the nodes will re-register although
	// the runtime is suspended.
	sc.Logger.Info("Restarting compute node to ensure it re-registers")
	if err = sc.Net.ComputeWorkers()[0].Stop(); err != nil {
		return fmt.Errorf("failed to stop node: %w", err)
	}
	if err = sc.Net.ComputeWorkers()[0].Start(); err != nil {
		return fmt.Errorf("failed to start node: %w", err)
	}

	// Another epoch transition to make sure the runtime keeps being suspended.
	if err = sc.epochTransition(ctx); err != nil {
		return err
	}

	// Wait for node updates again.
	if err = waitForNodeUpdates(); err != nil {
		return err
	}

	// Ensure that runtimes are still suspended.
	if err = ensureRuntimesSuspended(true); err != nil {
		return err
	}

	// Now escrow the stake back.
	sc.Logger.Info("escrowing stake back")
	var enoughStake quantity.Quantity
	_ = enoughStake.FromUint64(100_000)
	tx = staking.NewAddEscrowTx(nonce, &transaction.Fee{Gas: 10000}, &staking.Escrow{
		Account: entAddr,
		Amount:  enoughStake,
	})
	nonce++ // nolint: ineffassign
	sigTx, err = transaction.Sign(entSigner, tx)
	if err != nil {
		return fmt.Errorf("failed to sign escrow: %w", err)
	}
	if err = sc.Net.Controller().Consensus.SubmitTx(ctx, sigTx); err != nil {
		return fmt.Errorf("failed to escrow stake: %w", err)
	}

	// Another epoch transition to trigger node re-registration.
	if err = sc.epochTransition(ctx); err != nil {
		return err
	}

	// Wait for node updates yet again.
	if err = waitForNodeUpdates(); err != nil {
		return err
	}

	// Now runtimes should no longer be suspended.
	if err = ensureRuntimesSuspended(false); err != nil {
		return err
	}

	// Another epoch transition to elect committees.
	if err = sc.epochTransition(ctx); err != nil {
		return err
	}

	// Submit a runtime transaction to check whether the runtimes got resumed.
	sc.Logger.Info("submitting transaction to runtime")
	if _, err = sc.submitKeyValueRuntimeInsertTx(ctx, runtimeID, "hello", "final world for sure", rtNonce); err != nil {
		return err
	}

	return nil
}
