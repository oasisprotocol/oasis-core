package runtime

import (
	"context"
	"encoding/base64"
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// KeymanagerMasterSecrets is the keymanager master secret rotation scenario.
var KeymanagerMasterSecrets scenario.Scenario = newKmMasterSecretsImpl()

type kmMasterSecretsImpl struct {
	Scenario

	nonce uint64
}

func newKmMasterSecretsImpl() scenario.Scenario {
	return &kmMasterSecretsImpl{
		Scenario: *NewScenario(
			"keymanager-master-secrets",
			NewTestClient().WithScenario(InsertRemoveKeyValueEncScenario),
		),
	}
}

func (sc *kmMasterSecretsImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// Speed up the test.
	f.Network.Beacon.VRFParameters = &beacon.VRFParameters{
		Interval:             10,
		ProofSubmissionDelay: 2,
	}

	// Test requires multiple key managers.
	f.Keymanagers = []oasis.KeymanagerFixture{
		{Runtime: 0, Entity: 1},
		{Runtime: 0, Entity: 1},
		{Runtime: 0, Entity: 1},
	}

	return f, nil
}

func (sc *kmMasterSecretsImpl) Clone() scenario.Scenario {
	return &kmMasterSecretsImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *kmMasterSecretsImpl) Run(ctx context.Context, childEnv *env.Env) (err error) { // nolint: gocyclo
	cli := cli.New(childEnv, sc.Net, sc.Logger)

	// Start the network.
	if err = sc.Net.Start(); err != nil {
		return err
	}

	// Verify in the background that all published master secrets are unique.
	stop, err := sc.monitorMasterSecrets(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err2 := stop(); err == nil {
			err = err2
		}
	}()

	// Test that only one master secret is generated if rotations are disabled.
	if _, err = sc.WaitMasterSecret(ctx, 0); err != nil {
		return fmt.Errorf("master secret not generated: %w", err)
	}
	if err = sc.WaitEpochs(ctx, 5); err != nil {
		return err
	}

	sc.Logger.Info("verifying that exactly one master secret has been generated")

	status, err := sc.KeyManagerStatus(ctx)
	if err != nil {
		return err
	}
	if !status.IsInitialized || len(status.Checksum) == 0 || status.Generation != 0 {
		return fmt.Errorf("exactly one master secret should be generated if rotation is disabled %+v", status)
	}
	secret, err := sc.MasterSecret(ctx)
	if err != nil {
		return err
	}
	if secret.Secret.Generation != 0 {
		return fmt.Errorf("the last master secret should have generation zero")
	}

	// Enable master secret rotations.
	if err = sc.UpdateRotationInterval(ctx, childEnv, cli, 1, sc.nonce); err != nil {
		return err
	}
	sc.nonce++
	if _, err = sc.WaitMasterSecret(ctx, 3); err != nil {
		return err
	}

	// Test if all key managers can derive keys from all master secrets.
	if err = sc.CompareLongtermPublicKeys(ctx, []int{0, 1, 2}); err != nil {
		return err
	}

	// Test master secrets if only two/one manager is running.
	if err = sc.StopKeymanagers(ctx, []int{2}); err != nil {
		return err
	}
	if _, err = sc.WaitMasterSecret(ctx, 4); err != nil {
		return err
	}
	if err = sc.StopKeymanagers(ctx, []int{1}); err != nil {
		return err
	}
	if _, err = sc.WaitMasterSecret(ctx, 6); err != nil {
		return err
	}

	// Check how frequently secrets are rotated.
	interval := beacon.EpochTime(3)
	if err = sc.UpdateRotationInterval(ctx, childEnv, cli, interval, sc.nonce); err != nil {
		return err
	}
	sc.nonce++
	prev, err := sc.WaitMasterSecret(ctx, 7)
	if err != nil {
		return err
	}
	next, err := sc.WaitMasterSecret(ctx, 8)
	if err != nil {
		return err
	}
	if diff := next.RotationEpoch - prev.RotationEpoch; diff != interval {
		return fmt.Errorf("rotation interval is not correct: expected %d got %d", interval, diff)
	}

	// Disable master secret rotations.
	if err = sc.UpdateRotationInterval(ctx, childEnv, cli, 0, sc.nonce); err != nil {
		return err
	}
	sc.nonce++
	if err = sc.WaitEpochs(ctx, 3); err != nil {
		return err
	}

	// No more secrets should be generated.
	status, err = sc.KeyManagerStatus(ctx)
	if err != nil {
		return err
	}
	if status.Generation != next.Generation {
		return fmt.Errorf("master secret rotations should be disabled: got %d, expected %d", status.Generation, next.Generation)
	}

	return nil
}

func (sc *kmMasterSecretsImpl) monitorMasterSecrets(ctx context.Context) (func() error, error) {
	sc.Logger.Info("started watching master secrets to see if they are unique and ordered")

	total := 0
	secretsOk := true
	statusesOk := true
	checksums := make(map[string]struct{})
	stopCh := make(chan struct{})

	cancel := func() error {
		stopCh <- struct{}{}
		stopCh <- struct{}{}
		unique := len(checksums)

		sc.Logger.Info("stopped watching master secrets to see if they are unique and ordered",
			"unique", unique,
			"total", total,
		)

		switch {
		case total == 0:
			return fmt.Errorf("no master secrets published")
		case unique != total:
			return fmt.Errorf("master secrets not unique: unique %d, total %d,", unique, total)
		case !secretsOk:
			return fmt.Errorf("invalid master secrets")
		case !statusesOk:
			return fmt.Errorf("invalid key manager statuses")
		default:
			return nil
		}
	}

	// Monitor proposed secrets.
	go func() {
		mstCh, mstSub, err := sc.Net.ClientController().Keymanager.WatchMasterSecrets(ctx)
		if err != nil {
			return
		}
		defer mstSub.Close()

		var prev, next *keymanager.SignedEncryptedMasterSecret
		for {
			select {
			case <-stopCh:
				return
			case next = <-mstCh:
			}

			if next.Secret.ID != KeyManagerRuntimeID {
				continue
			}

			sc.Logger.Info("master secret published",
				"generation", next.Secret.Generation,
				"epoch", next.Secret.Epoch,
				"ciphertexts", len(next.Secret.Secret.Ciphertexts),
			)

			total++
			checksums[base64.StdEncoding.EncodeToString(next.Secret.Secret.Checksum)] = struct{}{}

			switch prev {
			case nil:
				if next.Secret.Generation != 0 {
					sc.Logger.Error("master secrets should start with zero generation",
						"generation", next.Secret.Generation,
					)
					secretsOk = false
				}
			default:
				if prev.Secret.Generation != next.Secret.Generation && prev.Secret.Generation != next.Secret.Generation-1 {
					sc.Logger.Error("master secret generations should be ordered",
						"prev", prev.Secret.Generation,
						"next", next.Secret.Generation,
					)
					secretsOk = false
				}
				if prev.Secret.Epoch >= next.Secret.Epoch {
					sc.Logger.Error("master secret epochs should be ordered",
						"prev", prev.Secret.Epoch,
						"next", next.Secret.Epoch,
					)
					secretsOk = false
				}
			}
			prev = next
		}
	}()

	// Monitor accepted secrets.
	go func() {
		stCh, stSub, err := sc.Net.ClientController().Keymanager.WatchStatuses(ctx)
		if err != nil {
			return
		}
		defer stSub.Close()

		var prev, next *keymanager.Status
		for {
			select {
			case <-stopCh:
				return
			case next = <-stCh:
			}

			if next.ID != KeyManagerRuntimeID {
				continue
			}

			sc.Logger.Info("key manager status updated",
				"generation", next.Generation,
				"rotation_epoch", next.RotationEpoch,
			)

			switch prev {
			case nil:
				if next.Generation != 0 {
					sc.Logger.Error("status should start with zero generation",
						"generation", next.Generation,
					)
					statusesOk = false
				}
			default:
				if prev.Generation != next.Generation && prev.Generation != next.Generation-1 {
					sc.Logger.Error("status should have ordered master secrets",
						"prev", prev.Generation,
						"next", next.Generation,
					)
					statusesOk = false
				}
				if prev.Generation != next.Generation && prev.RotationEpoch >= next.RotationEpoch {
					sc.Logger.Error("status should have ordered rotation epochs",
						"prev", prev.RotationEpoch,
						"next", next.RotationEpoch,
					)
					statusesOk = false
				}
			}
			prev = next
		}
	}()

	return cancel, nil
}
