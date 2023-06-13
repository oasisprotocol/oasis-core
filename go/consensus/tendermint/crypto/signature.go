// Package crypto implements tendermint specific cryptography.
package crypto

import (
	"github.com/cometbft/cometbft/crypto"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

var tendermintSignatureContext = signature.NewContext("oasis-core/tendermint")

// PublicKeyToTendermint converts a signature.PublicKey to the
// tendermint equivalent.
func PublicKeyToTendermint(k *signature.PublicKey) cmted25519.PubKey {
	tk := make(cmted25519.PubKey, cmted25519.PubKeySize)
	copy(tk[:], (*k)[:])
	return tk
}

// PublicKeyFromTendermint converts a tendermint public key to a
// signature.PublicKey.
func PublicKeyFromTendermint(tk *cmted25519.PubKey) signature.PublicKey {
	var k signature.PublicKey
	_ = k.UnmarshalBinary(tk.Bytes())
	return k
}

// SignerToTendermint converts a signature.Signer to the tendermint
// equivalent.
func SignerToTendermint(signer signature.Signer) crypto.PrivKey {
	return &tmSigner{
		inner: signer,
	}
}

type tmSigner struct {
	inner signature.Signer
}

func (s *tmSigner) Bytes() []byte {
	// I hope to god nothing actually calls this, basically ever.
	panic("consensus/tendermint/crypto: Bytes() operation not supported")
}

func (s *tmSigner) Sign(msg []byte) ([]byte, error) {
	return s.inner.ContextSign(tendermintSignatureContext, msg)
}

func (s *tmSigner) PubKey() crypto.PubKey {
	pk := s.inner.Public()
	return PublicKeyToTendermint(&pk)
}

func (s *tmSigner) Equals(other crypto.PrivKey) bool {
	return s.PubKey().Equals(other.PubKey())
}

func (s *tmSigner) Type() string {
	return "ed25519"
}

func init() {
	cmted25519.EnableOasisDomainSeparation(string(tendermintSignatureContext))
}
