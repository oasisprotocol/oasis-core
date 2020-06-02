// Package composite provides a composite signer.
package composite

import (
	"errors"
	"io"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

// SignerName is the name used to identify the composite signer.
const SignerName = "composite"

// FactoryConfig is the composite factory configuration.
type FactoryConfig map[signature.SignerRole]signature.SignerFactory

// SignerFactory is a SignerFactory that is a composite of multiple other
// SignerFactory(s).
type SignerFactory struct {
	inner FactoryConfig
}

// EnsureRole ensures that the SignerFactory is configured for the given
// role.
func (sf *SignerFactory) EnsureRole(role signature.SignerRole) error {
	for k := range sf.inner {
		if k == role {
			return nil
		}
	}
	return signature.ErrRoleMismatch
}

// Generate will generate and persist an new private key corresponding to
// the provided role, and return a Signer ready for use.
func (sf *SignerFactory) Generate(role signature.SignerRole, rng io.Reader) (signature.Signer, error) {
	factory, ok := sf.inner[role]
	if !ok {
		return nil, signature.ErrRoleMismatch
	}
	return factory.Generate(role, rng)
}

// Load will load the private key corresponding to the role, and return a Signer
// ready for use.
func (sf *SignerFactory) Load(role signature.SignerRole) (signature.Signer, error) {
	factory, ok := sf.inner[role]
	if !ok {
		return nil, signature.ErrRoleMismatch
	}
	return factory.Load(role)
}

// NewFactory creates a new factory with the specified roles, with the
// specified pre-created SignerFactory(s).
func NewFactory(config interface{}, roles ...signature.SignerRole) (signature.SignerFactory, error) {
	cfg, ok := config.(FactoryConfig)
	if !ok {
		return nil, errors.New("signature/signer/composite: invalid composite signer configuration provided")
	}
	sf := &SignerFactory{
		inner: make(FactoryConfig),
	}

	// Treat the roles vector as canonical.
	for _, v := range roles {
		factory, ok := cfg[v]
		if !ok || factory == nil {
			return nil, signature.ErrRoleMismatch
		}
		sf.inner[v] = factory
	}

	return sf, nil
}
