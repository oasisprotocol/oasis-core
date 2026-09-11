package runtime

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/quote"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// KeyManagerAccessPolicy is the key manager access policy e2e test scenario.
var KeyManagerAccessPolicy scenario.Scenario = newKeyManagerAccessPolicyImpl()

type keyManagerAccessPolicyImpl struct {
	Scenario

	upgradedRuntimeIndex int
}

func newKeyManagerAccessPolicyImpl() scenario.Scenario {
	return &keyManagerAccessPolicyImpl{
		Scenario: *NewScenario("keymanager-access-policy", NewTestClient().WithScenario(SimpleScenario)),
	}
}

func (sc *keyManagerAccessPolicyImpl) Clone() scenario.Scenario {
	return &keyManagerAccessPolicyImpl{
		Scenario:             *sc.Scenario.Clone().(*Scenario),
		upgradedRuntimeIndex: sc.upgradedRuntimeIndex,
	}
}

func (sc *keyManagerAccessPolicyImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// Start with a valid key manager access policy to ensure that compute runtimes can access the
	// key manager when their TEE capability satisfies the configured policy.
	f.Runtimes[1].KeyManagerAccessPolicy = &quote.Policy{
		IAS: &ias.QuotePolicy{Disabled: true},
		PCS: &pcs.QuotePolicy{
			TCBValidityPeriod:          90,
			MinTCBEvaluationDataNumber: 12,
		},
	}
	if sc.upgradedRuntimeIndex, err = sc.UpgradeComputeRuntimeFixture(f, true); err != nil {
		return nil, err
	}

	return f, nil
}

func (sc *keyManagerAccessPolicyImpl) Run(ctx context.Context, childEnv *env.Env) error {
	cli := cli.New(childEnv, sc.Net, sc.Logger)

	// First verify that the runtime works with a valid key manager access policy.
	if err := sc.StartNetworkAndWaitForClientSync(ctx); err != nil {
		return err
	}
	if err := sc.RunTestClientAndCheckLogs(ctx, childEnv); err != nil {
		return err
	}

	// Discover the upgrade bundle and serve it to nodes once the new deployment is registered.
	bundles, err := findBundles(sc.Net.BasePath())
	if err != nil {
		return err
	}
	rawURL := sc.Net.Clients()[0].Config.Runtime.Registries[0]
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	server := newBundleServer(parsedURL.Port(), bundles, sc.Logger)
	server.Start()
	defer server.Stop()

	// Make the future deployment's key manager access policy impossible to satisfy.
	rt := sc.Net.Runtimes()[sc.upgradedRuntimeIndex]
	rtDsc := rt.ToRuntimeDescriptor()
	var constraints node.SGXConstraints
	if err = cbor.Unmarshal(rtDsc.Deployments[1].TEE, &constraints); err != nil {
		return fmt.Errorf("failed to decode runtime SGX constraints: %w", err)
	}
	constraints.KeyManagerAccessPolicy = &quote.Policy{
		IAS: &ias.QuotePolicy{Disabled: true},
		PCS: &pcs.QuotePolicy{Disabled: true},
	}
	rtDsc.Deployments[1].TEE = cbor.Marshal(constraints)

	// Use the regular runtime upgrade flow to update the key manager enclave policy, register the
	// future deployment, hot-load its bundle, and wait for activation.
	if err = sc.EnableRuntimeDeployment(ctx, childEnv, cli, rt, 1, 0); err != nil {
		return err
	}

	// Each node should have attempted to register the new deployment and consensus should have
	// rejected its TEE capability specifically because of the restrictive access policy.
	const expectedRegistrationError = "pcs/quote: PCS quotes are disabled by policy"
	for _, worker := range sc.Net.ComputeWorkers() {
		ctrl, err := oasis.NewController(worker.SocketPath())
		if err != nil {
			return err
		}
		status, err := ctrl.GetStatus(ctx)
		ctrl.Close()
		if err != nil {
			return fmt.Errorf("failed to get status for compute worker %s: %w", worker.Name, err)
		}
		registration := status.Registration
		if registration == nil || registration.LastAttemptSuccessful {
			return fmt.Errorf("compute worker %s unexpectedly still registered", worker.Name)
		}
		if !strings.Contains(registration.LastAttemptErrorMessage, expectedRegistrationError) {
			return fmt.Errorf(
				"compute worker %s failed registration for an unexpected reason: %s",
				worker.Name,
				registration.LastAttemptErrorMessage,
			)
		}
	}

	return nil
}
