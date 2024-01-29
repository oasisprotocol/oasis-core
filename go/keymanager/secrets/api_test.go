package secrets

import (
	"testing"

	"github.com/stretchr/testify/require"

	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
)

func TestSignVerify(t *testing.T) {
	require := require.New(t)

	signer1 := memorySigner.NewTestSigner("signer1")
	signer2 := memorySigner.NewTestSigner("signer2")

	initResponse := InitResponse{
		IsSecure:       true,
		Checksum:       []byte{1, 2, 3, 4, 5},
		PolicyChecksum: []byte{5, 6, 7, 8, 9},
	}

	sigInitResponse, err := SignInitResponse(signer1, &initResponse)
	require.NoError(err, "signing should succeed")

	err = sigInitResponse.Verify(signer1.Public())
	require.NoError(err, "verification with public key should succeed")

	err = sigInitResponse.Verify(signer2.Public())
	require.Error(err, "verification with different public key should fail")
}

func TestStatus(t *testing.T) {
	require := require.New(t)

	// Uninitialized key manager.
	var s Status
	require.Equal(uint64(0), s.NextGeneration())

	// Key manager with one master secret generation.
	s.Checksum = []byte{1, 2, 3}
	require.Equal(uint64(1), s.NextGeneration())

	// Key manager with ten master secret generations.
	s.Generation = 9
	require.Equal(uint64(10), s.NextGeneration())
}
