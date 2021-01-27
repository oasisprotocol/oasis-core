package runtime

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

// KeymanagerUpgrade is the keymanager upgrade scenario.
var KeymanagerUpgrade scenario.Scenario = newKmUpgradeImpl()

type kmUpgradeImpl struct {
	runtimeImpl

	nonce uint64
}

func newKmUpgradeImpl() scenario.Scenario {
	return &kmUpgradeImpl{
		runtimeImpl: *newRuntimeImpl(
			"keymanager-upgrade",
			"simple-keyvalue-enc-client",
			[]string{
				"--key", "key1",
				"--seed", "first_seed",
			},
		),
	}
}

func (sc *kmUpgradeImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Load the upgraded keymanager binary.
	newKmBinaries := sc.resolveRuntimeBinaries([]string{"simple-keymanager-upgrade"})
	// Setup the upgraded runtime.
	kmRuntimeFix := f.Runtimes[0]
	if kmRuntimeFix.Kind != registry.KindKeyManager {
		return nil, fmt.Errorf("expected first runtime in fixture to be keymanager runtime, got: %s", kmRuntimeFix.Kind)
	}
	for _, tee := range []node.TEEHardware{node.TEEHardwareInvalid, node.TEEHardwareIntelSGX} {
		newKmBinaries[tee] = append(newKmBinaries[tee], kmRuntimeFix.Binaries[tee]...)
	}
	kmRuntimeFix.Binaries = newKmBinaries
	// The upgraded runtime will be registered later.
	kmRuntimeFix.ExcludeFromGenesis = true
	f.Runtimes = append(f.Runtimes, kmRuntimeFix)

	// Allow keymanager-0 to exit after replication is done.
	f.Keymanagers[0].AllowEarlyTermination = true

	// Add the upgraded keymanager, will be started later.
	f.Keymanagers = append(f.Keymanagers, oasis.KeymanagerFixture{Runtime: 2, Entity: 1, NoAutoStart: true})

	f.Network.IAS.UseRegistry = true

	return f, nil
}

func (sc *kmUpgradeImpl) Clone() scenario.Scenario {
	return &kmUpgradeImpl{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (sc *kmUpgradeImpl) applyUpgradePolicy(childEnv *env.Env) error {
	cli := cli.New(childEnv, sc.Net, sc.Logger)

	kmPolicyPath := filepath.Join(childEnv.Dir(), "km_policy.cbor")
	kmPolicySig1Path := filepath.Join(childEnv.Dir(), "km_policy_sig1.pem")
	kmPolicySig2Path := filepath.Join(childEnv.Dir(), "km_policy_sig2.pem")
	kmPolicySig3Path := filepath.Join(childEnv.Dir(), "km_policy_sig3.pem")
	kmUpdateTxPath := filepath.Join(childEnv.Dir(), "km_gen_update.json")

	oldKMRuntime := sc.Net.Runtimes()[0]
	newKMRuntime := sc.Net.Runtimes()[2]
	// Sanity check fixture.
	if err := func() error {
		if oldKMRuntime.Kind() != registry.KindKeyManager {
			return fmt.Errorf("old keymanager runtime not of kind KindKeyManager")
		}
		if newKMRuntime.Kind() != registry.KindKeyManager {
			return fmt.Errorf("new keymanager runtime not of kind KindKeyManager")
		}
		if oldKMRuntime.ID() != newKMRuntime.ID() {
			return fmt.Errorf("keymanager runtimes ID mismatch")
		}
		return nil
	}(); err != nil {
		return fmt.Errorf("keymanager runtimes fixture sanity check: %w", err)
	}

	oldKMEncID := oldKMRuntime.GetEnclaveIdentity()
	newKMEncID := newKMRuntime.GetEnclaveIdentity()

	if oldKMEncID == nil && newKMEncID == nil {
		sc.Logger.Info("No SGX runtimes, skipping policy update")
		return nil
	}

	// Ensure enclave IDs differ between the old and new runtimes.
	oldEncID, _ := oldKMEncID.MarshalText()
	newEncID, _ := newKMEncID.MarshalText()
	if bytes.Equal(oldEncID, newEncID) {
		return fmt.Errorf("expected different enclave identities, got: %s", newEncID)
	}

	// Build updated SGX policies.
	sc.Logger.Info("building new KM SGX policy enclave policies map")
	enclavePolicies := make(map[sgx.EnclaveIdentity]*keymanager.EnclavePolicySGX)

	enclavePolicies[*newKMEncID] = &keymanager.EnclavePolicySGX{}
	enclavePolicies[*newKMEncID].MayQuery = make(map[common.Namespace][]sgx.EnclaveIdentity)
	enclavePolicies[*oldKMEncID] = &keymanager.EnclavePolicySGX{}
	enclavePolicies[*oldKMEncID].MayQuery = make(map[common.Namespace][]sgx.EnclaveIdentity)

	// Allow new runtime enclave to replicate from the old runtime enclave.
	enclavePolicies[*oldKMEncID].MayReplicate = []sgx.EnclaveIdentity{*newKMEncID}

	// Allow compute runtime to query new runtime.
	for _, rt := range sc.Net.Runtimes() {
		if rt.Kind() != registry.KindCompute {
			continue
		}
		if eid := rt.GetEnclaveIdentity(); eid != nil {
			enclavePolicies[*newKMEncID].MayQuery[rt.ID()] = []sgx.EnclaveIdentity{*eid}
		}
	}

	sc.Logger.Info("initing updated KM policy")
	if err := cli.Keymanager.InitPolicy(oldKMRuntime.ID(), 2, enclavePolicies, kmPolicyPath); err != nil {
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

func (sc *kmUpgradeImpl) ensureReplicationWorked(ctx context.Context, km *oasis.Keymanager, rt *oasis.Runtime) error {
	ctrl, err := oasis.NewController(km.SocketPath())
	if err != nil {
		return err
	}
	node, err := ctrl.Registry.GetNode(
		ctx,
		&registry.IDQuery{
			ID: km.NodeID,
		},
	)
	if err != nil {
		return err
	}
	nodeRt := node.GetRuntime(rt.ID())
	if nodeRt == nil {
		return fmt.Errorf("node is missing keymanager runtime from descriptor")
	}
	var signedInitResponse keymanager.SignedInitResponse
	if err = cbor.Unmarshal(nodeRt.ExtraInfo, &signedInitResponse); err != nil {
		return fmt.Errorf("failed to unmarshal replica extrainfo")
	}

	// Grab a state dump and ensure all keymanager nodes have a matching
	// checksum.
	doc, err := ctrl.Consensus.StateToGenesis(context.Background(), 0)
	if err != nil {
		return fmt.Errorf("failed to obtain consensus state: %w", err)
	}
	if err = func() error {
		for _, status := range doc.KeyManager.Statuses {
			if !status.ID.Equal(&nodeRt.ID) {
				continue
			}
			if !status.IsInitialized {
				return fmt.Errorf("key manager failed to initialize")
			}
			if !bytes.Equal(status.Checksum, signedInitResponse.InitResponse.Checksum) {
				return fmt.Errorf("key manager failed to replicate, checksum mismatch")
			}
			return nil
		}
		return fmt.Errorf("consensus state missing km status")
	}(); err != nil {
		return err
	}

	return nil
}

func (sc *kmUpgradeImpl) Run(childEnv *env.Env) error {
	ctx := context.Background()
	cli := cli.New(childEnv, sc.Net, sc.Logger)

	clientErrCh, cmd, err := sc.runtimeImpl.start(childEnv)
	if err != nil {
		return err
	}
	sc.Logger.Info("waiting for client to exit")
	// Wait for the client to exit.
	select {
	case err = <-sc.Net.Errors():
		_ = cmd.Process.Kill()
	case err = <-clientErrCh:
	}
	if err != nil {
		return err
	}

	// Generate and update a policy that will allow replication for the new
	// keymanager.
	if err = sc.applyUpgradePolicy(childEnv); err != nil {
		return fmt.Errorf("updating policies: %w", err)
	}

	// Start the new keymanager.
	sc.Logger.Info("starting new keymanager")
	newKm := sc.Net.Keymanagers()[1]
	if err = newKm.Start(); err != nil {
		return fmt.Errorf("starting new key-manager: %w", err)
	}

	// Update runtime to include the new enclave identity.
	sc.Logger.Info("updating keymanager runtime descriptor")
	newRt := sc.Net.Runtimes()[2]
	kmRtDesc := newRt.ToRuntimeDescriptor()
	kmTxPath := filepath.Join(childEnv.Dir(), "register_update_km_runtime.json")
	if err = cli.Registry.GenerateRegisterRuntimeTx(sc.nonce, kmRtDesc, kmTxPath, ""); err != nil {
		return fmt.Errorf("failed to generate register KM runtime tx: %w", err)
	}
	sc.nonce++
	if err = cli.Consensus.SubmitTx(kmTxPath); err != nil {
		return fmt.Errorf("failed to update KM runtime: %w", err)
	}

	// Wait for the new node to register.
	sc.Logger.Info("waiting for new keymanager node to register",
		"num_nodes", sc.Net.NumRegisterNodes(),
	)
	if err = sc.Net.Keymanagers()[1].WaitReady(ctx); err != nil {
		return fmt.Errorf("error waiting for new keymanager to be ready: %w", err)
	}

	// Ensure replication succeeded.
	if err = sc.ensureReplicationWorked(ctx, newKm, newRt); err != nil {
		return err
	}

	// Shutdown old keymanager and make sure it deregisters.
	sc.Logger.Info("shutting down old keymanager")
	oldKm := sc.Net.Keymanagers()[0]
	if err = oldKm.RequestShutdown(ctx, true); err != nil {
		return fmt.Errorf("failed to request shutdown: %w", err)
	}

	// Run client again.
	sc.Logger.Info("starting a second client to check if key manager works")
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
