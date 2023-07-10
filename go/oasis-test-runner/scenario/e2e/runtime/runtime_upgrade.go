package runtime

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

// RuntimeUpgrade is the runtime upgrade scenario.
var RuntimeUpgrade scenario.Scenario = newRuntimeUpgradeImpl()

const versionActivationTimeout = 15 * time.Second

type runtimeUpgradeImpl struct {
	Scenario

	nonce uint64

	upgradedRuntimeIndex int
}

func newRuntimeUpgradeImpl() scenario.Scenario {
	return &runtimeUpgradeImpl{
		Scenario: *NewScenario(
			"runtime-upgrade",
			NewTestClient().WithScenario(InsertRemoveKeyValueEncScenario),
		),
	}
}

func (sc *runtimeUpgradeImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
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
	newRuntimeBinaries := sc.ResolveRuntimeBinaries(KeyValueRuntimeUpgradeBinary)

	// Setup the upgraded runtime (first is keymanager, others should be generic compute).
	runtimeFix := f.Runtimes[computeIndex]
	runtimeFix.Deployments = append([]oasis.DeploymentCfg{}, runtimeFix.Deployments...)
	runtimeFix.Deployments = append(runtimeFix.Deployments, oasis.DeploymentCfg{
		Version:  version.Version{Major: 0, Minor: 1, Patch: 0},
		Binaries: newRuntimeBinaries,
	})

	// The upgraded runtime will be registered later.
	runtimeFix.ExcludeFromGenesis = true
	sc.upgradedRuntimeIndex = len(f.Runtimes)
	f.Runtimes = append(f.Runtimes, runtimeFix)

	// Compute nodes should include the upgraded runtime version.
	for i := range f.ComputeWorkers {
		f.ComputeWorkers[i].Runtimes = []int{sc.upgradedRuntimeIndex}
	}
	// The client node should include the upgraded runtime version.
	f.Clients[0].Runtimes = []int{sc.upgradedRuntimeIndex}

	return f, nil
}

func (sc *runtimeUpgradeImpl) Clone() scenario.Scenario {
	return &runtimeUpgradeImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
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

	kmRuntimeEncID := kmRuntime.GetEnclaveIdentity(0)
	oldRuntimeEncID := oldRuntime.GetEnclaveIdentity(0)
	newRuntimeEncID := newRuntime.GetEnclaveIdentity(1)

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
	enclavePolicies[*kmRuntimeEncID].MayQuery = map[common.Namespace][]sgx.EnclaveIdentity{
		// Allow both old and new compute runtimes to query private data.
		newRuntime.ID(): {
			*oldRuntimeEncID,
			*newRuntimeEncID,
		},
	}

	sc.Logger.Info("initing updated KM policy")
	if err := cli.Keymanager.InitPolicy(kmRuntime.ID(), 2, 0, enclavePolicies, kmPolicyPath); err != nil {
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

func (sc *runtimeUpgradeImpl) Run(ctx context.Context, childEnv *env.Env) error {
	cli := cli.New(childEnv, sc.Net, sc.Logger)

	if err := sc.StartNetworkAndTestClient(ctx, childEnv); err != nil {
		return err
	}
	sc.Logger.Info("waiting for client to exit")
	// Wait for the client to exit.
	if err := sc.WaitTestClient(); err != nil {
		return err
	}

	// Make sure the old version is active on all compute nodes.
	newRt := sc.Net.Runtimes()[sc.upgradedRuntimeIndex]
	if err := sc.EnsureActiveVersionForComputeWorkers(ctx, newRt, version.MustFromString("0.0.0")); err != nil {
		return err
	}

	// Generate and update a policy that will allow the new runtime to run.
	if err := sc.applyUpgradePolicy(childEnv); err != nil {
		return fmt.Errorf("updating policies: %w", err)
	}

	// Fetch current epoch.
	epoch, err := sc.Net.Controller().Beacon.GetEpoch(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to get current epoch: %w", err)
	}
	upgradeEpoch := epoch + 3

	// Update runtime to include the new enclave identity.
	sc.Logger.Info("updating runtime descriptor")
	newRtDsc := newRt.ToRuntimeDescriptor()
	newRtDsc.Deployments[1].ValidFrom = upgradeEpoch

	newTxPath := filepath.Join(childEnv.Dir(), "register_update_compute_runtime.json")
	if err := cli.Registry.GenerateRegisterRuntimeTx(childEnv.Dir(), newRtDsc, sc.nonce, newTxPath); err != nil {
		return fmt.Errorf("failed to generate register compute runtime tx: %w", err)
	}
	sc.nonce++
	if err := cli.Consensus.SubmitTx(newTxPath); err != nil {
		return fmt.Errorf("failed to update compute runtime: %w", err)
	}

	// Wait for activation epoch.
	sc.Logger.Info("waiting for runtime upgrade epoch",
		"epoch", upgradeEpoch,
	)
	if err := sc.Net.Controller().Beacon.WaitEpoch(ctx, upgradeEpoch); err != nil {
		return fmt.Errorf("failed to wait for epoch: %w", err)
	}

	// Make sure the new version is active.
	if err := sc.EnsureActiveVersionForComputeWorkers(ctx, newRt, version.MustFromString("0.1.0")); err != nil {
		return err
	}

	// Run client again.
	sc.Logger.Info("starting a second client to check if runtime works")
	sc.Scenario.TestClient = NewTestClient().WithSeed("seed2").WithScenario(InsertRemoveKeyValueEncScenarioV2)
	return sc.RunTestClientAndCheckLogs(ctx, childEnv)
}
