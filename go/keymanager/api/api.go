// Package api implements the key manager management API and common data types.
package api

import (
	"context"
	"crypto/sha512"

	"github.com/oasisprotocol/curve25519-voi/primitives/x25519"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
)

const (
	// ModuleName is a unique module name for the keymanager module.
	ModuleName = "keymanager"
)

var (
	// InsecureRAK is the insecure hardcoded key manager public key, used
	// in insecure builds when a RAK is unavailable.
	InsecureRAK signature.PublicKey

	// InsecureREK is the insecure hardcoded key manager public key, used
	// in insecure builds when a REK is unavailable.
	InsecureREK x25519.PublicKey

	// TestSigners contains a list of signers with corresponding test keys, used
	// in insecure builds when a RAK is unavailable.
	TestSigners []signature.Signer

	// RPCMethodConnect is the name of the method used to establish a Noise session.
	RPCMethodConnect = ""
)

// Backend is a key manager management implementation.
type Backend interface {
	// StateToGenesis returns the genesis state at specified block height.
	StateToGenesis(ctx context.Context, height int64) (*Genesis, error)

	// Secrets returns the key manager secrets management implementation.
	Secrets() secrets.Backend
}

// Genesis is the key manager management genesis state.
type Genesis = secrets.Genesis

func init() {
	// Old `INSECURE_SIGNING_KEY_PKCS8`.
	var oldTestKey signature.PublicKey
	_ = oldTestKey.UnmarshalHex("9d41a874b80e39a40c9644e964f0e4f967100c91654bfd7666435fe906af060f")
	signature.RegisterTestPublicKey(oldTestKey)

	// Register all the seed derived SGX key manager test keys.
	for idx, v := range []string{
		"ekiden test key manager RAK seed", // DO NOT REORDER.
		"ekiden key manager test multisig key 0",
		"ekiden key manager test multisig key 1",
		"ekiden key manager test multisig key 2",
	} {
		tmpSigner := memorySigner.NewTestSigner(v)
		TestSigners = append(TestSigners, tmpSigner)

		if idx == 0 {
			InsecureRAK = tmpSigner.Public()
		}
	}

	rek := x25519.PrivateKey(sha512.Sum512_256([]byte("ekiden test key manager REK seed")))
	InsecureREK = *rek.Public()
}
