package plugin

import "github.com/oasisprotocol/oasis-core/go/common/crypto/signature"

// Signer is the interface that must be implemented by all signer plugins.
type Signer interface {
	// Initialize initializes the plugin with the provided configuration
	// and roles.
	Initialize(config string, roles ...signature.SignerRole) error

	// Load will load the private key corresponding to the provided role,
	// optionally generating a new keypair if requested.
	Load(role signature.SignerRole, mustGenerate bool) error

	// Public returns the public key corresponding to a given role.
	Public(role signature.SignerRole) (signature.PublicKey, error)

	// ContextSign generates a signature with the given role's private
	// key over the context and message.
	//
	// Note: Unlike the real signature.Signer interface, it is assumed
	// that the caller handles context registration and domain
	// separation.
	ContextSign(role signature.SignerRole, rawContext signature.Context, message []byte) ([]byte, error)
}
