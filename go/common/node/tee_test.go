package node

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/quote"
)

func TestTEEFeaturesSGXApplyDefaultConstraints(t *testing.T) {
	require := require.New(t)

	tf := TEEFeaturesSGX{
		PCS: true,
	}
	sc := SGXConstraints{}

	tf.ApplyDefaultConstraints(&sc)
	require.Nil(sc.Policy, "policy should remain nil when no default policy is configured")

	defaultIasPolicy := &ias.QuotePolicy{}
	defaultPcsPolicy := &pcs.QuotePolicy{
		TCBValidityPeriod:          10,
		MinTCBEvaluationDataNumber: 7,
	}

	tf = TEEFeaturesSGX{
		PCS: true,
		DefaultPolicy: &quote.Policy{
			IAS: defaultIasPolicy,
			PCS: defaultPcsPolicy,
		},
		DefaultMaxAttestationAge: 100,
	}
	sc = SGXConstraints{}

	tf.ApplyDefaultConstraints(&sc)
	require.NotNil(sc.Policy, "a default policy should be used")
	require.EqualValues(defaultIasPolicy, sc.Policy.IAS)
	require.EqualValues(defaultPcsPolicy, sc.Policy.PCS)
	require.EqualValues(100, sc.MaxAttestationAge)

	existingPcsPolicy := &pcs.QuotePolicy{
		TCBValidityPeriod:          20,
		MinTCBEvaluationDataNumber: 1,
	}

	sc = SGXConstraints{
		Policy: &quote.Policy{
			PCS: existingPcsPolicy,
		},
	}

	tf.ApplyDefaultConstraints(&sc)
	require.EqualValues(defaultIasPolicy, sc.Policy.IAS)
	require.EqualValues(existingPcsPolicy, sc.Policy.PCS)

	tf = TEEFeaturesSGX{
		PCS: false,
		DefaultPolicy: &quote.Policy{
			IAS: defaultIasPolicy,
			PCS: defaultPcsPolicy,
		},
	}
	sc = SGXConstraints{}

	tf.ApplyDefaultConstraints(&sc)
	require.NotNil(sc.Policy, "a default policy should be used")
	require.EqualValues(defaultIasPolicy, sc.Policy.IAS)
	require.Nil(sc.Policy.PCS, "PCS policy should remain unset when PCS is disabled")
}
