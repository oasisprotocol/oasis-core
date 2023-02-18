package state

import (
	"testing"

	"github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
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
	secrets := make([]*api.SignedEncryptedMasterSecret, 0, 10)
	for i := 0; i < cap(secrets); i++ {
		secret := api.SignedEncryptedMasterSecret{
			Secret: api.EncryptedMasterSecret{
				ID:         runtimes[i%2],
				Generation: uint64(i),
			},
		}
		secrets = append(secrets, &secret)
	}

	// Test adding secrets.
	for _, secret := range secrets {
		err := s.SetMasterSecret(ctx, secret)
		require.NoError(err, "SetMasterSecret()")
	}

	// Test querying secrets.
	for i, runtime := range runtimes {
		secret, err := s.MasterSecret(ctx, runtime)
		require.NoError(err, "MasterSecret()")
		require.Equal(secrets[8+i], secret, "last master secret should be kept")
	}
	_, err := s.MasterSecret(ctx, common.Namespace{1, 2, 3})
	require.EqualError(err, api.ErrNoSuchMasterSecret.Error(), "MasterSecret should error for non-existing secrets")
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
	secrets := make([]*api.SignedEncryptedEphemeralSecret, 0, 20)
	for i := 0; i < cap(secrets); i++ {
		secret := api.SignedEncryptedEphemeralSecret{
			Secret: api.EncryptedEphemeralSecret{
				ID:    runtimes[(i/5)%2],
				Epoch: beacon.EpochTime(i),
			},
		}
		secrets = append(secrets, &secret)
	}

	// Test adding secrets.
	for _, secret := range secrets {
		err := s.SetEphemeralSecret(ctx, secret)
		require.NoError(err, "SetEphemeralSecret()")
	}

	// Test querying secrets.
	for i := range secrets {
		secret, err := s.EphemeralSecret(ctx, secrets[i].Secret.ID, secrets[i].Secret.Epoch)
		require.NoError(err, "EphemeralSecret()")
		require.Equal(secrets[i], secret, "ephemeral secret should match")
	}
	for i := range secrets {
		_, err := s.EphemeralSecret(ctx, secrets[i].Secret.ID, secrets[i].Secret.Epoch+5)
		require.EqualError(err, api.ErrNoSuchEphemeralSecret.Error(), "EphemeralSecret should error for non-existing secrets")
	}

	// Test partial/complete secret removal.
	testCases := []struct {
		runtime common.Namespace
		epoch   beacon.EpochTime
		removed int
		kept    int
	}{
		// Remove all secrets for the first runtime.
		{
			runtimes[0],
			100,
			10,
			10,
		},
		// Remove 6 secrets (epochs 0-4, 10) for the first runtime.
		{
			runtimes[0],
			11,
			6,
			14,
		},
		// Remove all secrets for the second runtime.
		{
			runtimes[1],
			100,
			10,
			10,
		},
		// Remove 8 secrets (epochs 5-9, 15-17) for the second runtime.
		{
			runtimes[1],
			18,
			8,
			12,
		},
	}
	for _, tc := range testCases {
		for _, secret := range secrets {
			err := s.SetEphemeralSecret(ctx, secret)
			require.NoError(err, "SetEphemeralSecret()")
		}

		err := s.CleanEphemeralSecrets(ctx, tc.runtime, tc.epoch)
		require.NoError(err, "CleanEphemeralSecrets()")

		var removed, kept int
		for i := range secrets {
			secret, err := s.EphemeralSecret(ctx, secrets[i].Secret.ID, secrets[i].Secret.Epoch)
			switch {
			case secrets[i].Secret.ID == tc.runtime && secrets[i].Secret.Epoch < tc.epoch:
				require.EqualError(err, api.ErrNoSuchEphemeralSecret.Error(), "EphemeralSecret should error for non-existing secrets")
				removed++
			default:
				require.NoError(err, "EphemeralSecret()")
				require.Equal(secrets[i], secret, "ephemeral secret should match")
				kept++
			}
		}
		require.Equal(tc.removed, removed, "the number of removed ephemeral secrets is incorrect")
		require.Equal(tc.kept, kept, "the number of kept ephemeral secrets is incorrect")
	}
}
