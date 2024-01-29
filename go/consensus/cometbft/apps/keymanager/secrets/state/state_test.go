package state

import (
	"testing"

	"github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
)

func TestMasterSecret(t *testing.T) {
	require := require.New(t)

	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextBeginBlock)
	defer ctx.Close()

	s := NewMutableState(ctx.State())

	// Prepare data.
	runtimes := []common.Namespace{
		common.NewTestNamespaceFromSeed([]byte("runtime 1"), common.NamespaceKeyManager),
		common.NewTestNamespaceFromSeed([]byte("runtime 2"), common.NamespaceKeyManager),
	}
	masterSecrets := make([]*secrets.SignedEncryptedMasterSecret, 0, 10)
	for i := 0; i < cap(masterSecrets); i++ {
		secret := secrets.SignedEncryptedMasterSecret{
			Secret: secrets.EncryptedMasterSecret{
				ID:         runtimes[i%2],
				Generation: uint64(i),
			},
		}
		masterSecrets = append(masterSecrets, &secret)
	}

	// Test adding secrets.
	for _, secret := range masterSecrets {
		err := s.SetMasterSecret(ctx, secret)
		require.NoError(err, "SetMasterSecret()")
	}

	// Test querying secrets.
	for i, runtime := range runtimes {
		secret, err := s.MasterSecret(ctx, runtime)
		require.NoError(err, "MasterSecret()")
		require.Equal(masterSecrets[8+i], secret, "last master secret should be kept")
	}
	_, err := s.MasterSecret(ctx, common.Namespace{1, 2, 3})
	require.EqualError(err, secrets.ErrNoSuchMasterSecret.Error(), "MasterSecret should error for non-existing secrets")
}

func TestEphemeralSecret(t *testing.T) {
	require := require.New(t)

	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextBeginBlock)
	defer ctx.Close()

	s := NewMutableState(ctx.State())

	// Prepare data.
	runtimes := []common.Namespace{
		common.NewTestNamespaceFromSeed([]byte("runtime 1"), common.NamespaceKeyManager),
		common.NewTestNamespaceFromSeed([]byte("runtime 2"), common.NamespaceKeyManager),
	}
	masterSecrets := make([]*secrets.SignedEncryptedEphemeralSecret, 0, 10)
	for i := 0; i < cap(masterSecrets); i++ {
		secret := secrets.SignedEncryptedEphemeralSecret{
			Secret: secrets.EncryptedEphemeralSecret{
				ID:    runtimes[i%2],
				Epoch: beacon.EpochTime(i),
			},
		}
		masterSecrets = append(masterSecrets, &secret)
	}

	// Test adding secrets.
	for _, secret := range masterSecrets {
		err := s.SetEphemeralSecret(ctx, secret)
		require.NoError(err, "SetEphemeralSecret()")
	}

	// Test querying secrets.
	for i, runtime := range runtimes {
		secret, err := s.EphemeralSecret(ctx, runtime)
		require.NoError(err, "EphemeralSecret()")
		require.Equal(masterSecrets[8+i], secret, "last ephemeral secret should be kept")
	}
	_, err := s.EphemeralSecret(ctx, common.Namespace{1, 2, 3})
	require.EqualError(err, secrets.ErrNoSuchEphemeralSecret.Error(), "EphemeralSecret should error for non-existing secrets")
}
