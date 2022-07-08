// Package file provides a PEM file backed signer.
package file

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519/extra/ecvrf"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/pem"
)

const (
	privateKeyPemType    = "ED25519 PRIVATE KEY"
	staticEntropyPemType = "STATIC ENTROPY"

	filePerm = 0o600

	// SignerName is the name used to identify the file backed signer.
	SignerName = "file"

	// StaticEntropySize is the size of the provided static entropy.
	StaticEntropySize = 32
)

var (
	_ signature.SignerFactoryCtor     = NewFactory
	_ signature.SignerFactory         = (*Factory)(nil)
	_ signature.Signer                = (*Signer)(nil)
	_ signature.VRFSigner             = (*Signer)(nil)
	_ signature.StaticEntropyProvider = (*Signer)(nil)

	// FileEntityKey is the entity key filename.
	FileEntityKey = "entity.pem"
	// FileIdentityKey is the identity key filename.
	FileIdentityKey = "identity.pem"
	// FileP2PKey is the P2P key filename.
	FileP2PKey = "p2p.pem"
	// FileP2PStaticEntropy is the static P2P entropy filename.
	FileP2PStaticEntropy = "p2p_entropy.pem"
	// FileConsensusKey is the consensus key filename.
	FileConsensusKey = "consensus.pem"
	// FileVRFKey is the vrf key filename.
	FileVRFKey = "vrf.pem"

	rolePEMFiles = map[signature.SignerRole]string{
		signature.SignerEntity:    FileEntityKey,
		signature.SignerNode:      FileIdentityKey,
		signature.SignerP2P:       FileP2PKey,
		signature.SignerConsensus: FileConsensusKey,
		signature.SignerVRF:       FileVRFKey,
	}
)

// NewFactory creates a new factory with the specified roles, with the
// specified dataDir.
func NewFactory(config interface{}, roles ...signature.SignerRole) (signature.SignerFactory, error) {
	dataDir, ok := config.(string)
	if !ok {
		return nil, errors.New("signature/signer/file: invalid file signer configuration provided")
	}

	return &Factory{
		roles:   append([]signature.SignerRole{}, roles...),
		dataDir: dataDir,
	}, nil
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
		role:       role,
	}
	buf, err := signer.marshalPEM()
	if err != nil {
		return nil, err
	}
	if err = ioutil.WriteFile(fn, buf, filePerm); err != nil {
		return nil, err
	}

	switch role {
	case signature.SignerP2P:
		// Generate new static entropy for P2P signers.
		if err = fac.generateStaticEntropy(FileP2PStaticEntropy, signer, rng); err != nil {
			return nil, err
		}
	default:
	}

	return signer, nil
}

func (fac *Factory) generateStaticEntropy(fn string, signer *Signer, rng io.Reader) error {
	if _, err := rng.Read(signer.staticEntropy[:]); err != nil {
		return err
	}

	// Persist the entropy.
	buf, err := signer.marshalStaticEntropyPEM()
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filepath.Join(fac.dataDir, fn), buf, filePerm)
}

// Load will load the private key corresponding to the role, and return a Signer
// ready for use.
func (fac *Factory) Load(role signature.SignerRole) (signature.Signer, error) {
	if err := fac.EnsureRole(role); err != nil {
		return nil, err
	}
	fn := rolePEMFiles[role]
	return fac.doLoad(filepath.Join(fac.dataDir, fn), role)
}

// ForceLoad is evil and should be destroyed, however that requires
// fixing deployment, and the entity key for node registration mess.
func (fac *Factory) ForceLoad(fn string) (signature.Signer, error) {
	return fac.doLoad(fn, signature.SignerUnknown)
}

func (fac *Factory) loadPEM(fn string) ([]byte, error) {
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

	return ioutil.ReadAll(f)
}

func (fac *Factory) doLoad(fn string, role signature.SignerRole) (signature.Signer, error) {
	buf, err := fac.loadPEM(fn)
	if err != nil {
		return nil, err
	}

	var signer Signer
	if err = signer.unmarshalPEM(buf); err != nil {
		return nil, err
	}
	signer.role = role

	switch role {
	case signature.SignerP2P:
		// Load static entropy for P2P signers.
		err = fac.loadStaticEntropy(FileP2PStaticEntropy, &signer)
		switch err {
		case nil:
		case signature.ErrNotExist:
			// Old versions of the file signer didn't provide static entropy, generate some now.
			if err = fac.generateStaticEntropy(FileP2PStaticEntropy, &signer, rand.Reader); err != nil {
				return nil, err
			}
		default:
			return nil, err
		}
	default:
	}

	return &signer, nil
}

func (fac *Factory) loadStaticEntropy(fn string, signer *Signer) error {
	buf, err := fac.loadPEM(filepath.Join(fac.dataDir, fn))
	if err != nil {
		return err
	}

	return signer.unmarshalStaticEntropyPEM(buf)
}

// Signer is a PEM file backed Signer.
type Signer struct {
	privateKey    ed25519.PrivateKey
	role          signature.SignerRole
	staticEntropy [StaticEntropySize]byte
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

// Prove generates a VRF proof with the private key over the alpha.
func (s *Signer) Prove(alphaString []byte) ([]byte, error) {
	if s.role != signature.SignerVRF {
		return nil, signature.ErrInvalidRole
	}
	return ecvrf.Prove_v10(s.privateKey, alphaString), nil
}

// StaticEntropy returns PrivateKeySize bytes of cryptographic entropy that
// is independent from the Signer's private key.  The value of this entropy
// is constant for the lifespan of the signer's underlying key pair.
func (s *Signer) StaticEntropy() ([]byte, error) {
	if s.role != signature.SignerP2P {
		return nil, signature.ErrInvalidRole
	}
	return s.staticEntropy[:], nil
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

func (s *Signer) marshalStaticEntropyPEM() ([]byte, error) {
	return pem.Marshal(staticEntropyPemType, s.staticEntropy[:])
}

func (s *Signer) unmarshalStaticEntropyPEM(data []byte) error {
	data, err := pem.Unmarshal(staticEntropyPemType, data)
	if err != nil {
		return err
	}
	if len(data) != StaticEntropySize {
		return signature.ErrMalformedPrivateKey
	}

	copy(s.staticEntropy[:], data)

	return nil
}
