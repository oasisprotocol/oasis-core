package byzantine

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
)

func TestFakeCapabilitySGX(t *testing.T) {
	var nodeID signature.PublicKey
	_, fakeCapabilitiesSGX, err := initFakeCapabilitiesSGX(nodeID)
	require.NoError(t, err, "initFakeCapabilitiesSGX failed")

	cs := cbor.Marshal(node.SGXConstraints{
		Enclaves: []sgx.EnclaveIdentity{{}},
	})

	teeCfg := node.TEEFeatures{
		SGX: node.TEEFeaturesSGX{
			PCS:                true,
			SignedAttestations: true,
		},
	}

	ias.SetSkipVerify()
	ias.SetAllowDebugEnclaves()
	require.NoError(t, fakeCapabilitiesSGX.TEE.Verify(&teeCfg, time.Now(), 1, cs, nodeID), "fakeCapabilitiesSGX not valid")
}
