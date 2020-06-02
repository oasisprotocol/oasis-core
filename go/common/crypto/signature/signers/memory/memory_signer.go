// Package memory provides a memory backed Signer, primarily for use in testing.
package memory

import (
	goEd25519 "crypto/ed25519"
	"crypto/sha512"
	"io"

	"github.com/oasisprotocol/ed25519"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

// SignerName is the name used to identify the memory backed signer.
const SignerName = "memory"

var (
	_ signature.SignerFactory = (*Factory)(nil)
	_ signature.Signer        = (*Signer)(nil)
)

// Factory is a memory backed SignerFactory.
type Factory struct{}

// NewFactory creates a new Factory.
func NewFactory() signature.SignerFactory {
	return &Factory{}
}

// EnsureRole is a no-op for testing expedience.
func (fac *Factory) EnsureRole(role signature.SignerRole) error {
	return nil
}

// Generate will generate a new private key and return a Signer ready for use,
// using entropy from `rng`.
func (fac *Factory) Generate(role signature.SignerRole, rng io.Reader) (signature.Signer, error) {
	// Generate a new private key.
	_, privateKey, err := ed25519.GenerateKey(rng)
	if err != nil {
		return nil, err
	}

	return &Signer{
		privateKey: privateKey,
		role:       role,
	}, nil
}

// Load will return an error, as the factory does not support persistence.
func (fac *Factory) Load(role signature.SignerRole) (signature.Signer, error) {
	return nil, signature.ErrNotExist
}

// Signer is a memory backed Signer.
type Signer struct {
	privateKey ed25519.PrivateKey
	role       signature.SignerRole
}

// Public returns the PublicKey corresponding to the signer.
func (s *Signer) Public() signature.PublicKey {
	var pk signature.PublicKey
	_ = pk.UnmarshalBinary(s.privateKey.Public().(ed25519.PublicKey))
	return pk
}

// ContextSign generates a signature with the private key over the context and
// message.
func (s *Signer) ContextSign(context signature.Context, message []byte) ([]byte, error) {
	data, err := signature.PrepareSignerMessage(context, message)
	if err != nil {
		return nil, err
	}

	return ed25519.Sign(s.privateKey, data), nil
}

// String returns anything but the actual private key backing the Signer.
func (s *Signer) String() string {
	return "[redacted private key]"
}

// Reset tears down the Signer and obliterates any sensitive state if any.
func (s *Signer) Reset() {
	for idx := range s.privateKey {
		s.privateKey[idx] = 0
	}
}

// UnsafeBytes returns the byte representation of the private key.  This
// MUST be removed for HSM support.
func (s *Signer) UnsafeBytes() []byte {
	return s.privateKey[:]
}

// NewSigner creates a new signer.
func NewSigner(entropy io.Reader) (signature.Signer, error) {
	var factory Factory
	return factory.Generate(signature.SignerUnknown, entropy)
}

// NewFromRuntime creates a new signer from a runtime private key.
func NewFromRuntime(rtPrivKey goEd25519.PrivateKey) signature.Signer {
	return &Signer{
		privateKey: ed25519.NewKeyFromSeed(rtPrivKey.Seed()),
	}
}

// NewTestSigner generates a new signer deterministically from
// a test key name string, registers it as a test key, and returns
// the signer.
//
// This routine will panic on failure.
func NewTestSigner(name string) signature.Signer {
	seed := sha512.Sum512_256([]byte(name))

	signer := &Signer{
		privateKey: ed25519.NewKeyFromSeed(seed[:]),
	}
	signature.RegisterTestPublicKey(signer.Public())

	return signer
}
