// Package ledger provides a Ledger backed signer.
package ledger

import (
	"fmt"
	"io"

	ledger "github.com/zondax/ledger-oasis-go"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
)

const (
	// SignerName is the name used to identify the Ledger backed signer.
	SignerName = "ledger"
)

var (
	_ signature.SignerFactoryCtor = NewFactory
	_ signature.SignerFactory     = (*Factory)(nil)
	_ signature.Signer            = (*Signer)(nil)

	// SignerDerivationPath is the derivation path used for generating
	// the signature key on the Ledger device.
	SignerDerivationPath = []uint32{44, 118, 0, 0, 0}

	roleDerivationPaths = map[signature.SignerRole][]uint32{
		signature.SignerEntity: SignerDerivationPath,
	}
)

// Factory is a Ledger backed SignerFactory.
type Factory struct {
	roles   []signature.SignerRole
	address string
}

// NewFactory creates a new factory with the specified roles.
func NewFactory(address string, roles ...signature.SignerRole) signature.SignerFactory {
	return &Factory{
		roles:   append([]signature.SignerRole{}, roles...),
		address: address,
	}
}

// EnsureRole ensures that the SignatureFactory is configured for the given
// role.
func (fac *Factory) EnsureRole(role signature.SignerRole) error {
	for _, v := range fac.roles {
		if v == role {
			return nil
		}
	}
	return signature.ErrRoleMismatch
}

// Generate has the same functionality as Load, since all keys are generated
// on the Ledger device.
func (fac *Factory) Generate(role signature.SignerRole, _rng io.Reader) (signature.Signer, error) {
	return fac.Load(role)
}

// Load will create a Signer backed by a Ledger device by searching for
// a device with the expected address. If no address is provided, this will
// created a Signer with the first Ledger device it finds.
// The only role allowed is SignerEntity.
func (fac *Factory) Load(role signature.SignerRole) (signature.Signer, error) {
	path, ok := roleDerivationPaths[role]
	if !ok {
		return nil, fmt.Errorf("role %s is not supported when using the Ledger backed signer", role)
	}

	device, err := ledger.ConnectLedgerOasisApp(fac.address, path)
	if err != nil {
		return nil, err
	}

	return &Signer{device, path, nil}, nil
}

// Signer is a Ledger backed Signer.
type Signer struct {
	device    *ledger.LedgerOasis
	path      []uint32
	publicKey *signature.PublicKey
}

// Public retrieves the public key from the Ledger device.
func (s *Signer) Public() signature.PublicKey {
	if s.publicKey != nil {
		return *s.publicKey
	}

	var pubKey signature.PublicKey
	retrieved, err := s.device.GetPublicKeyEd25519(s.path)
	if err != nil {
		panic(fmt.Errorf("failed to retrieve public key from device: %w", err))
	}
	copy(pubKey[:], retrieved)
	s.publicKey = &pubKey
	return pubKey
}

// ContextSign generates a signature with the private key over the context and
// message.
func (s *Signer) ContextSign(context signature.Context, message []byte) ([]byte, error) {
	return s.device.SignEd25519(s.path, []byte(context), message)
}

// String returns the address of the account on the Ledger device.
func (s *Signer) String() string {
	return fmt.Sprintf("[ledger signer: %s]", s.Public())
}

// Reset tears down the Signer.
func (s *Signer) Reset() {
	s.device.Close()
}

// ListDevices lists all available Ledger devices by address.
func ListDevices() {
	ledger.ListOasisDevices(SignerDerivationPath)
}
