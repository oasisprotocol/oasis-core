package signature

import (
	"crypto/sha512"
	"encoding"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/oasisprotocol/ed25519"
)

const (
	chainContextMaxSize   = 64
	chainContextSeparator = " for chain "
)

var (
	// ErrNotExist is the error returned when a private key does not exist.
	ErrNotExist = os.ErrNotExist

	// ErrMalformedPrivateKey is the error returned when a private key is
	// malformed.
	ErrMalformedPrivateKey = errors.New("signature: malformed private key")

	// ErrRoleMismatch is the error returned when the signer factory role
	// is misconfigured.
	ErrRoleMismatch = errors.New("signature: signer factory role mismatch")

	// ErrRoleAction is the error returned when the signer role mismatches
	// the signing operations allowed by the role.
	ErrRoleAction = errors.New("signature: signer role action mismatch")

	// ErrInvalidRole is the error returned when the signer role is invalid.
	ErrInvalidRole = errors.New("signature: invalid signer role")

	errMalformedContext    = errors.New("signature: malformed context")
	errUnregisteredContext = errors.New("signature: unregistered context")
	errNoChainContext      = errors.New("signature: chain domain separation context not set")

	registeredContexts        sync.Map
	allowUnregisteredContexts bool

	chainContextLock sync.RWMutex
	chainContext     Context

	// SignerRoles is the list of all supported signer roles.
	SignerRoles = []SignerRole{
		SignerEntity,
		SignerNode,
		SignerP2P,
		SignerConsensus,
	}

	_ encoding.TextMarshaler   = (*SignerRole)(nil)
	_ encoding.TextUnmarshaler = (*SignerRole)(nil)
)

type contextOptions struct {
	chainSeparation bool
}

// ContextOption is a context configuration option.
type ContextOption func(*contextOptions)

// WithChainSeparation is a context option that enforces additional domain
// separation based on the ChainID.
func WithChainSeparation() ContextOption {
	return func(o *contextOptions) {
		o.chainSeparation = true
	}
}

// Context is a domain separation context.
type Context string

// NewContext creates and registers a new context.  This routine will panic
// if the context is malformed or is already registered.
func NewContext(rawContext string, opts ...ContextOption) Context {
	var opt contextOptions
	for _, v := range opts {
		v(&opt)
	}

	// Even if we are not using the clearly superior RFC 8032 constructs
	// enforce something that is compatible.
	//
	// Note: We disallow context lengths of 0, since our ContextSign call
	// is intended to enforce strict domain separation.
	l := len(rawContext)
	if l == 0 {
		panic(errMalformedContext)
	}
	if opt.chainSeparation {
		l += len(chainContextSeparator) + chainContextMaxSize
	}
	if l > ed25519.ContextMaxSize {
		panic(errMalformedContext)
	}

	// Disallow contexts including the chain context separator as a simple
	// way to avoid conflicts with chain-separated contexts.
	if strings.Contains(rawContext, chainContextSeparator) {
		panic("signature: context must not include '" + chainContextSeparator + "': '" + rawContext + "'")
	}

	ctx := Context(rawContext)
	if _, isRegistered := registeredContexts.Load(ctx); isRegistered {
		panic("signature: context already registered: '" + ctx + "'")
	}
	registeredContexts.Store(ctx, &opt)

	return ctx
}

// UnsafeResetChainContext resets the chain context.
//
// This function should NOT be used during normal operation as changing
// the chain context while an application is running is unsafe. The main
// use case for having this function is unit tests.
func UnsafeResetChainContext() {
	chainContextLock.Lock()
	defer chainContextLock.Unlock()

	chainContext = Context("")
}

// UnsafeAllowUnregisteredContexts bypasses the context registration check.
//
// This function is only for the benefit of implementing a remote signer.
func UnsafeAllowUnregisteredContexts() {
	allowUnregisteredContexts = true
}

// IsUnsafeUnregisteredContextsAllowed returns true iff context registration
// checks are bypassed.
func IsUnsafeUnregisteredContextsAllowed() bool {
	return allowUnregisteredContexts
}

// SetChainContext configures the chain domain separation context that is
// used with any contexts constructed using the WithChainSeparation option.
func SetChainContext(rawContext string) {
	if l := len(rawContext); l == 0 || l > chainContextMaxSize {
		panic(errMalformedContext)
	}

	chainContextLock.Lock()
	defer chainContextLock.Unlock()

	if chainContext != "" && rawContext != string(chainContext) {
		panic("signature: chain domain separation context already set: '" + chainContext + "'")
	}

	chainContext = Context(rawContext)
}

// SignerRole is the role of the Signer (Entity, Node, etc).
type SignerRole int

const (
	SignerUnknown   SignerRole = 0
	SignerEntity    SignerRole = 1
	SignerNode      SignerRole = 2
	SignerP2P       SignerRole = 3
	SignerConsensus SignerRole = 4

	SignerEntityName    = "entity"
	SignerNodeName      = "node"
	SignerP2PName       = "p2p"
	SignerConsensusName = "consensus"
)

// String returns the string representation of a SignerRole.
func (role SignerRole) String() string {
	switch role {
	case SignerEntity:
		return SignerEntityName
	case SignerNode:
		return SignerNodeName
	case SignerP2P:
		return SignerP2PName
	case SignerConsensus:
		return SignerConsensusName
	default:
		return "[unknown signer role]"
	}
}

// MarshalText encodes a SignerRole into text form.
func (role SignerRole) MarshalText() ([]byte, error) {
	return []byte(role.String()), nil
}

// UnmarshalText decodes a text slice into a SignerRole.
func (role *SignerRole) UnmarshalText(text []byte) error {
	switch string(text) {
	case SignerEntityName:
		*role = SignerEntity
	case SignerNodeName:
		*role = SignerNode
	case SignerP2PName:
		*role = SignerP2P
	case SignerConsensusName:
		*role = SignerConsensus
	default:
		return fmt.Errorf("%w: %s", ErrInvalidRole, string(text))
	}
	return nil
}

// SignerFactoryCtor is an SignerFactory constructor.
type SignerFactoryCtor func(interface{}, ...SignerRole) (SignerFactory, error)

// SignerFactory is the opaque factory interface for Signers.
type SignerFactory interface {
	// EnsureRole ensures that the SignerFactory is configured for the given
	// role.
	EnsureRole(role SignerRole) error

	// Generate will generate and persist an new private key corresponding to
	// the provided role, and return a Signer ready for use.  Certain
	// implementations require an entropy source to be provided.
	Generate(role SignerRole, rng io.Reader) (Signer, error)

	// Load will load the private key corresonding to the provided role, and
	// return a Signer ready for use.
	Load(role SignerRole) (Signer, error)
}

// Signer is an opaque interface for private keys that is capable of producing
// signatures, in the spirit of `crypto.Signer`.
type Signer interface {
	// Public returns the PublicKey corresponding to the signer.
	Public() PublicKey

	// ContextSign generates a signature with the private key over the context and
	// message.
	ContextSign(context Context, message []byte) ([]byte, error)

	// String returns the string representation of a Signer, which MUST not
	// include any sensitive information.
	String() string

	// Reset tears down the Signer and obliterates any sensitive state if any.
	Reset()
}

// UnsafeSigner is a Signer that also supports access to the raw private key,
// primarily for testing.
type UnsafeSigner interface {
	Signer

	// UnsafeBytes returns the byte representation of the private key.
	UnsafeBytes() []byte
}

// PrepareSignerContext prepares a context for use during signing by a Signer.
func PrepareSignerContext(context Context) ([]byte, error) {
	// The remote signer implementation uses the raw context, and
	// registration is dealt with client side.  Just check that the
	// length is sensible, even though the client should be sending
	// something sane.
	if allowUnregisteredContexts {
		if cLen := len(context); cLen == 0 || cLen > ed25519.ContextMaxSize {
			return nil, errMalformedContext
		}
		return []byte(context), nil
	}

	// Ensure that the context is registered for use.
	rawOpts, isRegistered := registeredContexts.Load(context)
	if !isRegistered {
		return nil, errUnregisteredContext
	}
	opts := rawOpts.(*contextOptions)

	// Include chain domain separation context if configured.
	if opts.chainSeparation {
		chainContextLock.RLock()
		defer chainContextLock.RUnlock()

		if chainContext == "" {
			return nil, errNoChainContext
		}
		context = context + chainContextSeparator + chainContext
	}

	return []byte(context), nil
}

// PrepareSignerMessage prepares a context and message for signing by a Signer.
func PrepareSignerMessage(context Context, message []byte) ([]byte, error) {
	rawContext, err := PrepareSignerContext(context)
	if err != nil {
		return nil, err
	}

	// This is stupid, and we should be using RFC 8032's Ed25519ph instead
	// but when an attempt was made to switch to it (See: #2103), people
	// complained that certain HSM offerings doesn't support it.
	//
	// Blame YubiHSM and Ledger, not me.
	h := sha512.New512_256()
	_, _ = h.Write(rawContext)
	_, _ = h.Write(message)
	sum := h.Sum(nil)

	return sum[:], nil
}
