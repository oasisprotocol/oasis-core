// Package crypto implements CometBFT specific cryptography.
package crypto

import (
	"github.com/cometbft/cometbft/crypto"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

// If you change this, also change TENDERMINT_CONTEXT in the Rust part of the
// code at runtime/src/consensus/tendermint/mod.rs.
var cometbftSignatureContext = signature.NewContext("oasis-core/tendermint")

// PublicKeyToCometBFT converts a signature.PublicKey to the
// CometBFT equivalent.
func PublicKeyToCometBFT(k *signature.PublicKey) cmted25519.PubKey {
	tk := make(cmted25519.PubKey, cmted25519.PubKeySize)
	copy(tk[:], (*k)[:])
	return tk
}

// PublicKeyFromCometBFT converts a CometBFT public key to a
// signature.PublicKey.
func PublicKeyFromCometBFT(tk *cmted25519.PubKey) signature.PublicKey {
	var k signature.PublicKey
	_ = k.UnmarshalBinary(tk.Bytes())
	return k
}

// SignerToCometBFT converts a signature.Signer to the CometBFT
// equivalent.
func SignerToCometBFT(signer signature.Signer) crypto.PrivKey {
	return &tmSigner{
		inner: signer,
	}
}

type tmSigner struct {
	inner signature.Signer
}

func (s *tmSigner) Bytes() []byte {
	// I hope to god nothing actually calls this, basically ever.
	panic("consensus/cometbft/crypto: Bytes() operation not supported")
}

func (s *tmSigner) Sign(msg []byte) ([]byte, error) {
	return s.inner.ContextSign(cometbftSignatureContext, msg)
}

func (s *tmSigner) PubKey() crypto.PubKey {
	pk := s.inner.Public()
	return PublicKeyToCometBFT(&pk)
}

func (s *tmSigner) Equals(other crypto.PrivKey) bool {
	return s.PubKey().Equals(other.PubKey())
}

func (s *tmSigner) Type() string {
	return "ed25519"
}

func init() {
	cmted25519.EnableOasisDomainSeparation(string(cometbftSignatureContext))
}
