package runtime

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

// RuntimeUpgrade is the runtime upgrade scenario.
var RuntimeUpgrade scenario.Scenario = newRuntimeUpgradeImpl()

type runtimeUpgradeImpl struct {
	runtimeImpl

	nonce uint64

	firstNewWorker int
}

func newRuntimeUpgradeImpl() scenario.Scenario {
	return &runtimeUpgradeImpl{
		runtimeImpl: *newRuntimeImpl(
			"runtime-upgrade",
			"simple-keyvalue-enc-client",
			nil,
		),
	}
}

func (sc *runtimeUpgradeImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Get number of compute runtimes.
	computeIndex := -1
	for i := range f.Runtimes {
		if f.Runtimes[i].Kind == registry.KindCompute {
			computeIndex = i
			break
		}
	}
	if computeIndex == -1 {
		return nil, fmt.Errorf("expected at least one compute runtime in the fixture, none found")
	}

	// Load the upgraded runtime binary.
	newRuntimeBinaries := sc.resolveRuntimeBinaries([]string{"simple-keyvalue-upgrade"})

	// Setup the upgraded runtime (first is keymanager, others should be generic compute).
	runtimeFix := f.Runtimes[computeIndex]
	for _, tee := range []node.TEEHardware{node.TEEHardwareInvalid, node.TEEHardwareIntelSGX} {
		newRuntimeBinaries[tee] = append(newRuntimeBinaries[tee], runtimeFix.Binaries[tee]...)
	}
	runtimeFix.Binaries = newRuntimeBinaries

	// The upgraded runtime will be registered later.
	runtimeFix.ExcludeFromGenesis = true
	newComputeIndex := len(f.Runtimes)
	f.Runtimes = append(f.Runtimes, runtimeFix)

	// Add the upgraded compute runtimes to the compute workers, will be started later.
	sc.firstNewWorker = len(f.ComputeWorkers)
	for i := range f.ComputeWorkers {
		f.ComputeWorkers[i].AllowEarlyTermination = true // Allow stopping the worker early.
		f.ComputeWorkers[i].Runtimes = []int{computeIndex}
	}
	for i := 0; i < sc.firstNewWorker; i++ {
		f.ComputeWorkers = append(f.ComputeWorkers, oasis.ComputeWorkerFixture{Entity: 1, NoAutoStart: true, Runtimes: []int{newComputeIndex}})
	}

	// The runtime ID stays the same, so pass only one instance to the storage workers.
	for i := range f.StorageWorkers {
		f.StorageWorkers[i].Runtimes = []int{computeIndex}
	}

	return f, nil
}

func (sc *runtimeUpgradeImpl) Clone() scenario.Scenario {
	return &runtimeUpgradeImpl{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (sc *runtimeUpgradeImpl) applyUpgradePolicy(childEnv *env.Env) error {
	cli := cli.New(childEnv, sc.Net, sc.Logger)

	kmPolicyPath := filepath.Join(childEnv.Dir(), "km_policy.cbor")
	kmPolicySig1Path := filepath.Join(childEnv.Dir(), "km_policy_sig1.pem")
	kmPolicySig2Path := filepath.Join(childEnv.Dir(), "km_policy_sig2.pem")
	kmPolicySig3Path := filepath.Join(childEnv.Dir(), "km_policy_sig3.pem")
	kmUpdateTxPath := filepath.Join(childEnv.Dir(), "km_gen_update.json")

	kmRuntime := sc.Net.Runtimes()[0]
	oldRuntime := sc.Net.Runtimes()[1]
	newRuntime := sc.Net.Runtimes()[2]
	// Sanity check fixture.
	if err := func() error {
		if kmRuntime.Kind() != registry.KindKeyManager {
			return fmt.Errorf("keymanager runtime not of kind KindKeyManager")
		}
		if oldRuntime.Kind() != registry.KindCompute {
			return fmt.Errorf("old runtime not of kind KindCompute")
		}
		if newRuntime.Kind() != registry.KindCompute {
			return fmt.Errorf("new runtime not of kind KindCompute")
		}
		if oldRuntime.ID() != newRuntime.ID() {
			return fmt.Errorf("runtime ID mismatch")
		}
		return nil
	}(); err != nil {
		return fmt.Errorf("runtimes fixture sanity check: %w", err)
	}

	kmRuntimeEncID := kmRuntime.GetEnclaveIdentity()
	oldRuntimeEncID := oldRuntime.GetEnclaveIdentity()
	newRuntimeEncID := newRuntime.GetEnclaveIdentity()

	if oldRuntimeEncID == nil && newRuntimeEncID == nil {
		sc.Logger.Info("No SGX runtimes, skipping policy update")
		return nil
	}

	// Ensure enclave IDs differ between the old and new runtimes.
	oldEncID, _ := oldRuntimeEncID.MarshalText()
	newEncID, _ := newRuntimeEncID.MarshalText()
	if bytes.Equal(oldEncID, newEncID) {
		return fmt.Errorf("expected different enclave identities, got: %s", newEncID)
	}

	// Build updated SGX policies.
	sc.Logger.Info("building new KM SGX policy enclave policies map")
	enclavePolicies := make(map[sgx.EnclaveIdentity]*keymanager.EnclavePolicySGX)

	enclavePolicies[*kmRuntimeEncID] = &keymanager.EnclavePolicySGX{}
	enclavePolicies[*kmRuntimeEncID].MayQuery = make(map[common.Namespace][]sgx.EnclaveIdentity)

	// Allow new compute runtimes to query private data.
	for _, rt := range sc.Net.Runtimes() {
		if rt.Kind() != registry.KindCompute {
			continue
		}
		if eid := rt.GetEnclaveIdentity(); eid != nil {
			enclavePolicies[*kmRuntimeEncID].MayQuery[rt.ID()] = []sgx.EnclaveIdentity{*eid}
		}
	}

	sc.Logger.Info("initing updated KM policy")
	if err := cli.Keymanager.InitPolicy(kmRuntime.ID(), 2, enclavePolicies, kmPolicyPath); err != nil {
		return err
	}
	sc.Logger.Info("signing updated KM policy")
	if err := cli.Keymanager.SignPolicy("1", kmPolicyPath, kmPolicySig1Path); err != nil {
		return err
	}
	if err := cli.Keymanager.SignPolicy("2", kmPolicyPath, kmPolicySig2Path); err != nil {
		return err
	}
	if err := cli.Keymanager.SignPolicy("3", kmPolicyPath, kmPolicySig3Path); err != nil {
		return err
	}

	sc.Logger.Info("updating KM policy")
	if err := cli.Keymanager.GenUpdate(sc.nonce, kmPolicyPath, []string{kmPolicySig1Path, kmPolicySig2Path, kmPolicySig3Path}, kmUpdateTxPath); err != nil {
		return err
	}
	if err := cli.Consensus.SubmitTx(kmUpdateTxPath); err != nil {
		return fmt.Errorf("failed to update KM policy: %w", err)
	}
	sc.nonce++

	return nil
}

func (sc *runtimeUpgradeImpl) Run(childEnv *env.Env) error {
	ctx := context.Background()
	cli := cli.New(childEnv, sc.Net, sc.Logger)

	clientErrCh, cmd, err := sc.runtimeImpl.start(childEnv)
	if err != nil {
		return err
	}
	sc.Logger.Info("waiting for client to exit")
	// Wait for the client to exit.
	select {
	case err = <-sc.runtimeImpl.Net.Errors():
		_ = cmd.Process.Kill()
	case err = <-clientErrCh:
	}
	if err != nil {
		return err
	}

	// Generate and update a policy that will allow the new runtime to run.
	if err = sc.applyUpgradePolicy(childEnv); err != nil {
		return fmt.Errorf("updating policies: %w", err)
	}

	// Stop old compute workers, making sure they deregister.
	sc.Logger.Info("stopping old runtimes")
	for i := 0; i < sc.firstNewWorker; i++ {
		worker := sc.Net.ComputeWorkers()[i]
		if err = worker.RequestShutdown(ctx, false); err != nil {
			return fmt.Errorf("failed to request shutdown: %w", err)
		}
	}
	// Wait for all old workers to exit.
	for i := 0; i < sc.firstNewWorker; i++ {
		worker := sc.Net.ComputeWorkers()[i]
		if err = <-worker.Exit(); err != env.ErrEarlyTerm {
			return fmt.Errorf("compute worker exited with error: %w", err)
		}
	}

	// Start the new compute workers.
	sc.Logger.Info("starting new runtimes")
	for i := sc.firstNewWorker; i < len(sc.Net.ComputeWorkers()); i++ {
		newWorker := sc.Net.ComputeWorkers()[i]
		if err = newWorker.Start(); err != nil {
			return fmt.Errorf("starting new compute worker: %w", err)
		}
	}

	// Update runtime to include the new enclave identity.
	sc.Logger.Info("updating runtime descriptor")
	newRt := sc.Net.Runtimes()[len(sc.Net.Runtimes())-1]
	newRtDesc := newRt.ToRuntimeDescriptor()
	newTxPath := filepath.Join(childEnv.Dir(), "register_update_compute_runtime.json")
	if err = cli.Registry.GenerateRegisterRuntimeTx(sc.nonce, newRtDesc, newTxPath, ""); err != nil {
		return fmt.Errorf("failed to generate register compute runtime tx: %w", err)
	}
	sc.nonce++
	if err = cli.Consensus.SubmitTx(newTxPath); err != nil {
		return fmt.Errorf("failed to update compute runtime: %w", err)
	}

	// Wait for the new nodes to register.
	sc.Logger.Info("waiting for new compute workers to be ready")
	for i := sc.firstNewWorker; i < len(sc.Net.ComputeWorkers()); i++ {
		if err = sc.Net.ComputeWorkers()[i].WaitReady(ctx); err != nil {
			return fmt.Errorf("error waiting for compute node to become ready: %w", err)
		}
	}

	// Run client again.
	sc.Logger.Info("starting a second client to check if runtime works")
	sc.runtimeImpl.clientArgs = []string{
		"--key", "key2",
		"--seed", "second_seed",
	}
	cmd, err = sc.startClient(childEnv)
	if err != nil {
		return err
	}
	client2ErrCh := make(chan error)
	go func() {
		client2ErrCh <- cmd.Wait()
	}()
	return sc.wait(childEnv, cmd, client2ErrCh)
}
