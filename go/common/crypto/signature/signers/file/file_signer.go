// Package file provides a PEM file backed signer.
package file

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ed25519"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/pem"
)

const (
	privateKeyPemType = "ED25519 PRIVATE KEY"

	filePerm = 0600
)

var (
	_ signature.SignerFactoryCtor = NewFactory
	_ signature.SignerFactory     = (*Factory)(nil)
	_ signature.Signer            = (*Signer)(nil)

	// FileEntityKey is the entity key filename.
	FileEntityKey = "entity.pem"
	// FileIdentityKey is the identity key filename.
	FileIdentityKey = "identity.pem"
	// FileP2PKey is the P2P key filename.
	FileP2PKey = "p2p.pem"

	rolePEMFiles = map[signature.SignerRole]string{
		signature.SignerEntity: FileEntityKey,
		signature.SignerNode:   FileIdentityKey,
		signature.SignerP2P:    FileP2PKey,
	}
)

// NewFactory creates a new factory with the specified roles, with the
// specified dataDir.
func NewFactory(dataDir string, roles ...signature.SignerRole) signature.SignerFactory {
	return &Factory{
		roles:   append([]signature.SignerRole{}, roles...),
		dataDir: dataDir,
	}
}

// Factory is a PEM file backed SignerFactory.
type Factory struct {
	roles   []signature.SignerRole
	dataDir string
}

// EnsureRole ensures that the SignerFactory is configured for the given
// role.
func (fac *Factory) EnsureRole(role signature.SignerRole) error {
	for _, v := range fac.roles {
		if v == role {
			return nil
		}
	}
	return signature.ErrRoleMismatch
}

// Generate will generate and persist a new private key corresponding to the
// role, and return a Signer ready for use, using entropy from `rng`.
func (fac *Factory) Generate(role signature.SignerRole, rng io.Reader) (signature.Signer, error) {
	if err := fac.EnsureRole(role); err != nil {
		return nil, err
	}
	// Ensure that we aren't trying to overrwrite an existing key.
	fn := rolePEMFiles[role]
	fn = filepath.Join(fac.dataDir, fn)
	f, err := os.Open(fn)
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
	if err = ioutil.WriteFile(fn, buf, filePerm); err != nil {
		return nil, err
	}

	return signer, nil
}

// Load will load the private key corresponding to the role, and return a Signer
// ready for use.
func (fac *Factory) Load(role signature.SignerRole) (signature.Signer, error) {
	if err := fac.EnsureRole(role); err != nil {
		return nil, err
	}
	fn := rolePEMFiles[role]
	return fac.doLoad(filepath.Join(fac.dataDir, fn))
}

// ForceLoad is evil and should be destroyed, however that requires
// fixing deployment, and the entity key for node registration mess.
func (fac *Factory) ForceLoad(fn string) (signature.Signer, error) {
	return fac.doLoad(fn)
}

func (fac *Factory) doLoad(fn string) (signature.Signer, error) {
	f, err := os.Open(fn)
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
		return nil, fmt.Errorf("signature/signer/file: invalid PEM file permissions %o on %s", fi.Mode(), fn)
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
