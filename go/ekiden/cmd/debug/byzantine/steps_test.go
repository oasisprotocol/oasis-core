package byzantine

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/sgx/ias"
)

func TestFakeCapabilitySGX(t *testing.T) {
	ias.SetSkipVerify()
	require.NoError(t, fakeCapabilitiesSGX.TEE.Verify(time.Now()), "fakeCapabilitiesSGX not valid")
}
