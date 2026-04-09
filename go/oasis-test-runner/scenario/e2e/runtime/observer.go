package runtime

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	controlAPI "github.com/oasisprotocol/oasis-core/go/control/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	runtimeClient "github.com/oasisprotocol/oasis-core/go/runtime/client/api"
)

const (
	observerTestKey   = "observer_test_key"
	observerTestValue = "observer_test_value"
)

// ObserverMode is the observer mode e2e test scenario.
var ObserverMode scenario.Scenario = newObserverModeImpl()

type observerModeImpl struct {
	Scenario
}

func newObserverModeImpl() scenario.Scenario {
	return &observerModeImpl{
		Scenario: *NewScenario(
			"observer",
			NewTestClient().WithScenario(NewTestClientScenario([]any{
				InsertKeyValueTx{
					Key:   observerTestKey,
					Value: observerTestValue,
					Kind:  encryptedWithSecretsTxKind,
				},
			})),
		),
	}
}

func (sc *observerModeImpl) Clone() scenario.Scenario {
	return &observerModeImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *observerModeImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// Add additional entity on top of two inherited from the default scenario.
	f.Entities = append(f.Entities, oasis.EntityCfg{})

	// Only entity 1 may register with the observer role.
	f.Runtimes[1].AdmissionPolicy = oasis.RuntimeAdmissionPolicyFixture{
		PerRole: map[node.RolesMask]oasis.PerRoleAdmissionPolicyFixture{
			node.RoleObserver: {
				EntityWhitelist: &oasis.EntityWhitelistRoleAdmissionPolicyFixture{
					Entities: map[int]registry.EntityWhitelistRoleConfig{
						1: {},
					},
				},
			},
		},
	}

	f.Observers = append(f.Observers, oasis.ObserverFixture{
		Entity:             1,
		Runtimes:           []int{1},
		RuntimeProvisioner: f.Clients[0].RuntimeProvisioner,
	})
	f.Observers = append(f.Observers, oasis.ObserverFixture{
		Entity:             2,
		Runtimes:           []int{1},
		RuntimeProvisioner: f.Clients[0].RuntimeProvisioner,
	})

	return f, nil
}

func (sc *observerModeImpl) Run(ctx context.Context, childEnv *env.Env) error {
	if err := sc.StartNetworkAndWaitForClientSync(ctx); err != nil {
		return err
	}

	if err := sc.StartTestClient(ctx, childEnv); err != nil {
		return err
	}
	if err := sc.WaitTestClient(); err != nil {
		return err
	}

	whitelisted := sc.Net.Observers()[0]
	nonWhitelisted := sc.Net.Observers()[1]

	defaultClientCtrl := sc.Net.ClientController()
	whitelistedCtrl, err := oasis.NewController(whitelisted.SocketPath())
	if err != nil {
		return fmt.Errorf("failed to create controller for whitelisted observer: %w", err)
	}
	defer whitelistedCtrl.Close()
	nonWhitelistedCtrl, err := oasis.NewController(nonWhitelisted.SocketPath())
	if err != nil {
		return fmt.Errorf("failed to create controller for non-whitelisted observer: %w", err)
	}
	defer nonWhitelistedCtrl.Close()

	// Sanity: ensure whitelisted observer has registered and non-whitelisted failed to prevent false positives.
	if err = sc.waitObserverRegistration(ctx, whitelistedCtrl, true); err != nil {
		return err
	}
	if err = sc.waitObserverRegistration(ctx, nonWhitelistedCtrl, false); err != nil {
		return err
	}

	sc.Logger.Info("ensuring client cannot query encrypted value")
	if _, err = sc.queryEncryptedKey(ctx, defaultClientCtrl, observerTestKey); err == nil { // If NO error
		return fmt.Errorf("client unexpectedly queried encrypted value successfully")
	}

	sc.Logger.Info("ensuring whitelisted observer can query encrypted value")
	value, err := sc.queryEncryptedKey(ctx, whitelistedCtrl, observerTestKey)
	if err != nil {
		return fmt.Errorf("whitelisted observer failed querying encrypted value: %w", err)
	}
	if value != observerTestValue {
		return fmt.Errorf("whitelisted observer query returned unexpected value (got: %s, want: %s)", value, observerTestValue)
	}

	sc.Logger.Info("checking non-whitelisted observer cannot query encrypted value")
	if _, err = sc.queryEncryptedKey(ctx, nonWhitelistedCtrl, observerTestKey); err == nil {
		return fmt.Errorf("non-whitelisted observer unexpectedly queried encrypted value successfully")
	}

	return nil
}

func (sc *observerModeImpl) queryEncryptedKey(ctx context.Context, ctrl *oasis.Controller, key string) (string, error) {
	resp, err := ctrl.RuntimeClient.Query(ctx, &runtimeClient.QueryRequest{
		RuntimeID: KeyValueRuntimeID,
		Round:     roothash.RoundLatest,
		Method:    "enc_get",
		Args:      cbor.Marshal(GetCall{Key: key}),
	})
	if err != nil {
		return "", fmt.Errorf("failed to query encrypted key: %w", err)
	}

	var rsp string
	if err = cbor.Unmarshal(resp.Data, &rsp); err != nil {
		return "", err
	}

	return rsp, nil
}

func (sc *observerModeImpl) waitObserverRegistration(ctx context.Context, ctrl *oasis.Controller, mustRegister bool) error {
	sc.Logger.Info("waiting for observer registration result", "must_register", mustRegister)

	reg, err := sc.waitObserverRegistrationAttempt(ctx, ctrl)
	if err != nil {
		return err
	}

	// Must not register
	if !mustRegister {
		if reg.LastAttemptSuccessful {
			return fmt.Errorf("observer unexpectedly registered successfully")
		}

		sc.Logger.Info("observer registration failed as expected")
		return nil
	}

	// Must register
	if !reg.LastAttemptSuccessful {
		return fmt.Errorf("observer failed to register: %s", reg.LastAttemptErrorMessage)
	}
	if !reg.Descriptor.HasRoles(node.RoleObserver) {
		return fmt.Errorf("observer registered without observer role: %s", reg.Descriptor.Roles)
	}
	sc.Logger.Info("observer registered as expected")
	return nil
}

func (sc *observerModeImpl) waitObserverRegistrationAttempt(ctx context.Context, ctrl *oasis.Controller) (*controlAPI.RegistrationStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	for {
		status, err := ctrl.GetStatus(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get observer status: %w", err)
		}

		reg := status.Registration
		if reg != nil && !reg.LastAttempt.IsZero() {
			return reg, nil
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("observer did not attempt registration within timeout: %w", ctx.Err())
		case <-time.After(time.Second):
		}
	}
}
