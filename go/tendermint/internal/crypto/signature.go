// Package crypto implementes tendermint specific cryptography.
package crypto

import (
	tmed "github.com/tendermint/tendermint/crypto/ed25519"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
)

// PublicKeyToTendermint converts a signature.PublicKey to the
// tendermint equivalent.
func PublicKeyToTendermint(k *signature.PublicKey) tmed.PubKeyEd25519 {
	var tk tmed.PubKeyEd25519
	copy(tk[:], (*k)[:])
	return tk
}

// PublicKeyFromTendermint converts a tendermint public key to a
// signature.PublicKey.
func PublicKeyFromTendermint(tk *tmed.PubKeyEd25519) signature.PublicKey {
	var k signature.PublicKey
	_ = k.UnmarshalBinary(tk[:])
	return k
}

// PrivateKeyToTendermint converts a signature.PrivateKey to the
// tendermint equivalent.
func PrivateKeyToTendermint(k *signature.PrivateKey) tmed.PrivKeyEd25519 {
	var tk tmed.PrivKeyEd25519
	copy(tk[:], (*k)[:])
	return tk
}

// PrivateKeyFromTendermint converts a tendermint private key to a
// signature.PrivateKey
func PrivateKeyFromTendermint(tk *tmed.PrivKeyEd25519) signature.PrivateKey {
	var k signature.PrivateKey
	_ = k.UnmarshalBinary(tk[:])
	return k
}
