package secrets

import (
	"crypto/sha512"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/curve25519-voi/primitives/x25519"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
)

func TestEncryptedSecret(t *testing.T) {
	require := require.New(t)

	// Create a secret encrypted for a key manager committee with 3 members.
	sec, reks := generateTestSecret(3)

	// Happy path (encrypted for all 3 enclaves).
	err := sec.SanityCheck(reks)
	require.NoError(err)

	// Happy path (encrypted for 2 enclaves).
	for pk := range sec.Ciphertexts {
		delete(sec.Ciphertexts, pk)
		break
	}

	err = sec.SanityCheck(reks)
	require.NoError(err)

	// Not enough ciphertexts (encrypted for 1 enclave only).
	for pk := range sec.Ciphertexts {
		delete(sec.Ciphertexts, pk)
		break
	}

	err = sec.SanityCheck(reks)
	require.EqualError(err, "keymanager: sanity check failed: secret is not encrypted with enough keys")

	// An unknown key (encrypted for an unknown enclave).
	sk := x25519.PrivateKey(sha512.Sum512_256([]byte("unknown")))
	pk := sk.Public()
	sec.Ciphertexts[*pk] = []byte{}

	err = sec.SanityCheck(reks)
	require.EqualError(err, "keymanager: sanity check failed: secret is encrypted with an unknown key")

	// Empty key manager committee.
	err = sec.SanityCheck(nil)
	require.EqualError(err, "keymanager: sanity check failed: secret has to be encrypted with at least one key")
}

func TestEncryptedMasterSecret(t *testing.T) {
	require := require.New(t)

	// Create a secret encrypted for a key manager committee with 3 members.
	sec, reks := generateTestSecret(3)

	// Wrap it in a master secret.
	gen := uint64(0)
	epoch := beacon.EpochTime(100)
	encSec := EncryptedMasterSecret{
		ID:         common.NewTestNamespaceFromSeed([]byte("runtime 1"), common.NamespaceKeyManager),
		Generation: gen,
		Epoch:      epoch,
		Secret:     sec,
	}

	// Happy path.
	err := encSec.SanityCheck(gen, epoch, reks)
	require.NoError(err)

	// Invalid generation.
	err = encSec.SanityCheck(gen+1, epoch, reks)
	require.EqualError(err, "keymanager: sanity check failed: master secret contains an invalid generation: (expected: 1, got: 0)")

	// Invalid generation.
	err = encSec.SanityCheck(gen, epoch+1, reks)
	require.EqualError(err, "keymanager: sanity check failed: master secret contains an invalid epoch: (expected: 101, got: 100)")

	// Empty key manager committee (make sure the secret is also checked).
	err = encSec.SanityCheck(gen, epoch, nil)
	require.EqualError(err, "keymanager: sanity check failed: secret has to be encrypted with at least one key")
}

func TestEncryptedEphemeralSecret(t *testing.T) {
	require := require.New(t)

	// Create a secret encrypted for a key manager committee with 3 members.
	sec, reks := generateTestSecret(3)

	// Wrap it in an ephemeral secret.
	epoch := beacon.EpochTime(100)
	encSec := EncryptedEphemeralSecret{
		ID:     common.NewTestNamespaceFromSeed([]byte("runtime 1"), common.NamespaceKeyManager),
		Epoch:  epoch,
		Secret: sec,
	}

	// Happy path.
	err := encSec.SanityCheck(epoch, reks)
	require.NoError(err)

	// Invalid epoch.
	err = encSec.SanityCheck(epoch+1, reks)
	require.EqualError(err, "keymanager: sanity check failed: ephemeral secret contains an invalid epoch: (expected: 101, got: 100)")

	// Empty key manager committee (make sure the secret is also checked).
	err = encSec.SanityCheck(epoch, nil)
	require.EqualError(err, "keymanager: sanity check failed: secret has to be encrypted with at least one key")
}

func generateTestSecret(n int) (EncryptedSecret, map[x25519.PublicKey]struct{}) {
	reks := make(map[x25519.PublicKey]struct{})
	ciphertexts := make(map[x25519.PublicKey][]byte)

	for i := 0; i < n; i++ {
		sk := x25519.PrivateKey(sha512.Sum512_256([]byte(fmt.Sprintf("rek %d", i))))
		pk := sk.Public()
		reks[*pk] = struct{}{}
		ciphertexts[*pk] = []byte{}
	}

	sec := EncryptedSecret{
		Checksum:    []byte{},
		PubKey:      x25519.PublicKey{},
		Ciphertexts: ciphertexts,
	}

	return sec, reks
}
