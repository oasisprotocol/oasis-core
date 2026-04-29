package runtime

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/quote"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// KeyManagerAccessPolicy is the key manager access policy e2e test scenario.
var KeyManagerAccessPolicy scenario.Scenario = newKeyManagerAccessPolicyImpl()

type keyManagerAccessPolicyImpl struct {
	Scenario
}

func newKeyManagerAccessPolicyImpl() scenario.Scenario {
	return &keyManagerAccessPolicyImpl{
		Scenario: *NewScenario("keymanager-access-policy", NewTestClient().WithScenario(SimpleScenario)),
	}
}

func (sc *keyManagerAccessPolicyImpl) Clone() scenario.Scenario {
	return &keyManagerAccessPolicyImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *keyManagerAccessPolicyImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	f.Runtimes[1].KeyManagerAccessPolicy = &quote.Policy{
		PCS: &pcs.QuotePolicy{
			TCBValidityPeriod:          90,
			MinTCBEvaluationDataNumber: 12,
		},
	}

	return f, nil
}

func (sc *keyManagerAccessPolicyImpl) Run(ctx context.Context, childEnv *env.Env) error {
	if err := sc.StartNetworkAndTestClient(ctx, childEnv); err != nil {
		return err
	}

	return sc.WaitTestClientAndCheckLogs()
}
