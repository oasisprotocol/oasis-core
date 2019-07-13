// Package file provides a PEM file backed signer.
package file

import (
	"errors"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/ed25519"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/pem"
)

const (
	privateKeyPemType = "ED25519 PRIVATE KEY"

	filePerm = 0600
)

var (
	_ signature.SignerFactoryCtor = NewFactory
	_ signature.SignerFactory     = (*Factory)(nil)
	_ signature.Signer            = (*Signer)(nil)
)

// NewFactory creates a new factory with the specified role.
func NewFactory(role signature.SignerRole) signature.SignerFactory {
	return &Factory{
		role: role,
	}
}

// Factory is a PEM file backed SignerFactory.
type Factory struct {
	role signature.SignerRole
}

// EnsureRole ensures that the SignerFactory is configured for the given
// role.
func (fac *Factory) EnsureRole(role signature.SignerRole) error {
	if fac.role != role {
		return signature.ErrRoleMismatch
	}
	return nil
}

// Generate will generate and persist a new private key to a PEM file at the
// path `id`, and return a Signer ready for use, using entropy from `rng`.
func (fac *Factory) Generate(id string, rng io.Reader) (signature.Signer, error) {
	// Ensure that we aren't trying to overrwrite an existing key.
	f, err := os.Open(id) // nolint: gosec
	if err == nil {
		f.Close()
		return nil, errors.New("signature/signer/file: key already exists")
	}
	if !os.IsNotExist(err) {
		return nil, err
	}

	// Generate a new private key.
	_, privateKey, err := ed25519.GenerateKey(rng)
	if err != nil {
		return nil, err
	}

	// Persist the private key.
	signer := &Signer{
		privateKey: privateKey,
	}
	buf, err := signer.marshalPEM()
	if err != nil {
		return nil, err
	}
	if err = ioutil.WriteFile(id, buf, filePerm); err != nil {
		return nil, err
	}

	return signer, nil
}

// Load will load the private key corresonding to id, and return a Signer ready
// for use.
func (fac *Factory) Load(id string) (signature.Signer, error) {
	f, err := os.Open(id) // nolint: gosec
	if err != nil {
		if os.IsNotExist(err) {
			return nil, signature.ErrNotExist
		}
		return nil, err
	}
	defer f.Close()

	// Ensure the PEM file has correct permissions.
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm() != filePerm {
		return nil, errors.New("signature/signer/file: invalid PEM file permissions")
	}

	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var signer Signer
	if err = signer.unmarshalPEM(buf); err != nil {
		return nil, err
	}

	return &signer, nil
}

// Signer is a PEM file backed Signer.
type Signer struct {
	privateKey ed25519.PrivateKey
}

// Public returns the PublicKey corresponding to the signer.
func (s *Signer) Public() signature.PublicKey {
	return signature.PublicKey(s.privateKey.Public().(ed25519.PublicKey))
}

// Sign generates a signature with the private key over the message.
func (s *Signer) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.privateKey, message), nil
}

// ContextSign generates a signature with the private key over the context and
// message.
func (s *Signer) ContextSign(context, message []byte) ([]byte, error) {
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

func (s *Signer) marshalPEM() ([]byte, error) {
	return pem.Marshal(privateKeyPemType, s.privateKey[:])
}

func (s *Signer) unmarshalPEM(data []byte) error {
	data, err := pem.Unmarshal(privateKeyPemType, data)
	if err != nil {
		return err
	}
	if len(data) != ed25519.PrivateKeySize {
		return signature.ErrMalformedPrivateKey
	}

	s.privateKey = ed25519.PrivateKey(data)

	return nil
}
