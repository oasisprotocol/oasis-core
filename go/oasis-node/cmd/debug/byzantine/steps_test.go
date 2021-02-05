package byzantine

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
)

func TestFakeCapabilitySGX(t *testing.T) {
	_, fakeCapabilitiesSGX, err := initFakeCapabilitiesSGX()
	require.NoError(t, err, "initFakeCapabilitiesSGX failed")

	cs := cbor.Marshal(sgx.Constraints{
		Enclaves: []sgx.EnclaveIdentity{{}},
	})

	ias.SetSkipVerify()
	ias.SetAllowDebugEnclaves()
	require.NoError(t, fakeCapabilitiesSGX.TEE.Verify(time.Now(), cs), "fakeCapabilitiesSGX not valid")
}
