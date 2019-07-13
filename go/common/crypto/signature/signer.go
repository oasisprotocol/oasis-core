package signature

import (
	"crypto/sha512"
	"errors"
	"io"
	"os"
)

// ContextSize is the size of a signature context in bytes.
const ContextSize = 8

var (
	// ErrNotExist is the error returned when a private key does not exist.
	ErrNotExist = os.ErrNotExist

	// ErrMalformedPrivateKey is the error returned when a private key is
	// malformed.
	ErrMalformedPrivateKey = errors.New("signature: malformed private key")

	// ErrRoleMismatch is the error returned when the signer factory role
	// is misconfigured.
	ErrRoleMismatch = errors.New("signature: signer factory role mismatch")

	errMalformedContext = errors.New("signature: malformed context")
)

// SignerRole is the role of the Signer (Entity, Node, etc).
type SignerRole int

const (
	SignerUnknown SignerRole = iota
	SignerEntity
	SignerNode
)

// SignerFactoryCtor is an SignerFactory constructor.
type SignerFactoryCtor func(SignerRole) SignerFactory

// SignerFactory is the opaque factory interface for Signers.
type SignerFactory interface {
	// EnsureRole ensures that the SignerFactory is configured for the given
	// role.
	EnsureRole(role SignerRole) error

	// Generate will generate and persist an new private key corresponding to
	// id, and return a Signer ready for use.  Certain implementations require
	// an entropy source to be provided.
	Generate(id string, rng io.Reader) (Signer, error)

	// Load will load the private key corresonding to id, and return
	// a Signer ready for use.
	Load(id string) (Signer, error)
}

// Signer is an opaque interface for private keys that is capable of producing
// signatures, in the spirit of `crypto.Signer`.
type Signer interface {
	// Public returns the PublicKey corresponding to the signer.
	Public() PublicKey

	// Sign generates a signature with the private key over the message.
	Sign(message []byte) ([]byte, error)

	// ContextSign generates a signature with the private key over the context and
	// message.
	ContextSign(context, message []byte) ([]byte, error)

	// String returns the string representation of a Signer, which MUST not
	// include any sensitive information.
	String() string

	// Reset tears down the Signer and obliterates any sensitive state if any.
	Reset()

	// UnsafeBytes returns the byte representation of the private key.  This
	// MUST be removed for HSM support.
	UnsafeBytes() []byte
}

// PrepareSignerMessage prepares a context and message for signing by a Signer.
func PrepareSignerMessage(context, message []byte) ([]byte, error) {
	if len(context) != ContextSize {
		return nil, errMalformedContext
	}

	// TODO: This is stupid and we should just sign context || message instead.
	h := sha512.New512_256()
	_, _ = h.Write(context)
	_, _ = h.Write(message)
	sum := h.Sum(nil)

	return sum[:], nil
}
