package node

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/quote"
)

func TestTEEFeaturesSGXApplyDefaultPolicy(t *testing.T) {
	require := require.New(t)

	tf := TEEFeaturesSGX{
		PCS: true,
	}

	policy := tf.ApplyDefaultPolicy(nil)
	require.Nil(policy, "policy should remain nil when no default policy is configured")

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
	}

	policy = tf.ApplyDefaultPolicy(nil)
	require.NotNil(policy, "a default policy should be used")
	require.EqualValues(defaultIasPolicy, policy.IAS)
	require.EqualValues(defaultPcsPolicy, policy.PCS)

	existingPcsPolicy := &pcs.QuotePolicy{
		TCBValidityPeriod:          20,
		MinTCBEvaluationDataNumber: 1,
	}

	policy = tf.ApplyDefaultPolicy(&quote.Policy{
		PCS: existingPcsPolicy,
	})
	require.EqualValues(defaultIasPolicy, policy.IAS)
	require.EqualValues(existingPcsPolicy, policy.PCS)

	tf = TEEFeaturesSGX{
		PCS: false,
		DefaultPolicy: &quote.Policy{
			IAS: defaultIasPolicy,
			PCS: defaultPcsPolicy,
		},
	}

	policy = tf.ApplyDefaultPolicy(nil)
	require.NotNil(policy, "a default policy should be used")
	require.EqualValues(defaultIasPolicy, policy.IAS)
	require.Nil(policy.PCS, "PCS policy should remain unset when PCS is disabled")
}
