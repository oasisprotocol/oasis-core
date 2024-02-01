package runtime

import (
	"context"
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/registry/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// KeymanagerRotationFailure is a scenario where the first master secret proposal is rejected
// because not enough nodes have replicated the secret. The second proposal is accepted,
// ensuring that nodes can properly handle potential reverts.
//
// Scenario:
//   - Start all key managers.
//   - Verify that master secret generation works.
//   - Stop the third key manager.
//   - Verify that the next proposal is not accepted.
//   - Repeat these steps N times.
var KeymanagerRotationFailure scenario.Scenario = newKmRotationFailureImpl()

type kmRotationFailureImpl struct {
	Scenario
}

func newKmRotationFailureImpl() scenario.Scenario {
	return &kmRotationFailureImpl{
		Scenario: *NewScenario("keymanager-rotation-failure", nil),
	}
}

func (sc *kmRotationFailureImpl) Clone() scenario.Scenario {
	return &kmRotationFailureImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *kmRotationFailureImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// Speed up the test.
	f.Network.Beacon.VRFParameters = &beacon.VRFParameters{
		Interval:             10,
		ProofSubmissionDelay: 2,
	}

	// We don't need compute workers.
	f.ComputeWorkers = []oasis.ComputeWorkerFixture{}

	// This requires multiple keymanagers.
	f.Keymanagers = []oasis.KeymanagerFixture{
		{Runtime: 0, Entity: 1, Policy: 0},
		{Runtime: 0, Entity: 1, Policy: 0},
		{Runtime: 0, Entity: 1, Policy: 0},
	}

	// Enable master secret rotation.
	// The rotation interval should be set to at least 2 so that key manager nodes can be shut down
	// after they have accepted the last generation but before a new master secret is proposed.
	f.KeymanagerPolicies[0].MasterSecretRotationInterval = 2

	return f, nil
}

func (sc *kmRotationFailureImpl) Run(ctx context.Context, _ *env.Env) error {
	var generation uint64

	// Start the first key manager.
	if err := sc.Net.Start(); err != nil {
		return err
	}

	for i := 0; i < 2; i++ {
		// Verify that master secret generation works with all key managers.
		for j := 0; j < 1; j++ {
			if err := sc.verifyMasterSecret(ctx, generation, 3); err != nil {
				return err
			}
			generation++
		}

		// Give key managers enough time to apply the last proposal and register with the latests
		// checksum. This process can take several blocks.
		if _, err := sc.WaitBlocks(ctx, 5); err != nil {
			return err
		}

		// Stop two key managers, leaving only 33% of the committee members to be active.
		if err := sc.StopKeymanagers([]int{1, 2}); err != nil {
			return err
		}

		// Extend registrations to ensure that stopped key managers remain on the committee.
		if err := sc.extendKeymanagerRegistrations(ctx, []int{1, 2}); err != nil {
			return err
		}

		// Verify that the next few master secret proposals are rejected.
		// Note that the proposals will be rejected only until the registrations
		// of the stopped key managers expire.
		if err := sc.verifyMasterSecretRejections(ctx, 3); err != nil {
			return err
		}

		// Verify that master secret generation works with one key manager
		// after registrations expire.
		for j := 0; j < 1; j++ {
			if err := sc.verifyMasterSecret(ctx, generation, 1); err != nil {
				return err
			}
			generation++
		}

		// Start stopped key managers.
		//
		// Note: Starting both key managers while they are still registered
		// may lead to a scenario where they both attempt to replicate ephemeral
		// secrets from each other. Since they are both still uninitialized,
		// replication requests will fail and retries will block initialization
		// for 15 seconds.
		if err := sc.StartKeymanagers([]int{1, 2}); err != nil {
			return err
		}

		// Key managers that have been started should join the committee in
		// the following epoch, unless consensus sync takes a lot of time.
		// Due to uncertainty about the committee size, we skip validation
		// of the next generation.
		if _, err := sc.WaitMasterSecret(ctx, generation); err != nil {
			return err
		}
		generation++
	}

	return nil
}

func (sc *kmRotationFailureImpl) verifyMasterSecret(ctx context.Context, generation uint64, committeeSize int) error {
	status, err := sc.WaitMasterSecret(ctx, generation)
	if err != nil {
		return fmt.Errorf("master secret was not generated: %w", err)
	}
	if status.Generation != generation {
		return fmt.Errorf("master secret generation number is not correct: expected %d, got %d", generation, status.Generation)
	}
	if size := len(status.Nodes); size != committeeSize {
		return fmt.Errorf("key manager committee's size is not correct: expected %d, got %d", committeeSize, size)
	}
	return nil
}

func (sc *kmRotationFailureImpl) extendKeymanagerRegistrations(ctx context.Context, idxs []int) error {
	sc.Logger.Info("extending registrations of the key managers", "ids", fmt.Sprintf("%+v", idxs))

	// Compute the maximum expiration epoch.
	epoch, err := sc.Net.ClientController().Beacon.GetEpoch(ctx, consensus.HeightLatest)
	if err != nil {
		return err
	}
	params, err := sc.Net.ClientController().Consensus.Registry().ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return err
	}
	expiration := uint64(epoch) + params.MaxNodeExpiration

	for _, idx := range idxs {
		km := sc.Net.Keymanagers()[idx]

		// Update expiration.
		nodeDesc, err := sc.Net.ClientController().Registry.GetNode(ctx, &api.IDQuery{
			Height: consensus.HeightLatest,
			ID:     km.NodeID,
		})
		if err != nil {
			return err
		}
		nodeDesc.Expiration = expiration

		// Prepare, sign and submit the register node transaction.
		identity, err := km.LoadIdentity()
		if err != nil {
			return err
		}
		nodeSigners := []signature.Signer{
			identity.NodeSigner,
			identity.P2PSigner,
			identity.ConsensusSigner,
			identity.VRFSigner,
			identity.TLSSigner,
		}
		sigNode, err := node.MultiSignNode(nodeSigners, registry.RegisterNodeSignatureContext, nodeDesc)
		if err != nil {
			return err
		}
		nonce, err := sc.Net.Controller().Consensus.GetSignerNonce(ctx, &consensus.GetSignerNonceRequest{
			AccountAddress: staking.NewAddress(identity.NodeSigner.Public()),
			Height:         consensus.HeightLatest,
		})
		if err != nil {
			return err
		}
		tx := registry.NewRegisterNodeTx(nonce, &transaction.Fee{Gas: 11000}, sigNode)
		sigTx, err := transaction.Sign(identity.NodeSigner, tx)
		if err != nil {
			return err
		}
		err = sc.Net.Controller().Consensus.SubmitTx(ctx, sigTx)
		if err != nil {
			return err
		}
	}

	return nil
}

func (sc *kmRotationFailureImpl) verifyMasterSecretRejections(ctx context.Context, n int) error {
	mstCh, mstSub, err := sc.Net.Controller().Keymanager.WatchMasterSecrets(ctx)
	if err != nil {
		return err
	}
	defer mstSub.Close()

	generations := make(map[uint64]struct{})

	for j := 0; j < n; j++ {
		select {
		case secret := <-mstCh:
			sc.Logger.Info("master secret proposed",
				"generation", secret.Secret.Generation,
				"epoch", secret.Secret.Epoch,
				"num_ciphertexts", len(secret.Secret.Secret.Ciphertexts),
			)

			generations[secret.Secret.Generation] = struct{}{}

			if len(generations) != 1 {
				return fmt.Errorf("master secret proposal was not rejected")
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}
