// Package api implementes the key manager management API and common data types.
package api

import (
	"context"
	"errors"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	registry "github.com/oasislabs/ekiden/go/registry/api"
)

var (
	// ErrNoSuchKeyManager is the error returned when a key manager does not
	// exist.
	ErrNoSuchKeyManager = errors.New("keymanager: no such key manager")

	// TestPublicKey is the insecure hardcoded key manager public key, used
	// in insecure builds when a RAK is unavailable.
	TestPublicKey signature.PublicKey

	initResponseContext = []byte("EkKmIniR")
)

// Status is the current key manager status.
type Status struct {
	// ID is the runtime ID of the key manager.
	ID signature.PublicKey `codec:"id"`

	// IsInitialized is true iff the key manager is done initializing.
	IsInitialized bool `codec:"is_initialized"`

	// IsSecure is true iff the key manger is secure.
	IsSecure bool `codec:"is_secure"`

	// Checksum is the key manager master secret verification checksum.
	Checksum []byte `codec:"checksum"`

	// Nodes is the list of currently active key manager node IDs.
	Nodes []signature.PublicKey `codec:"nodes"`

	// Policy is the key manager policy.
	Policy *SignedPolicySGX `codec:"policy"`
}

// Backend is a key manager management implementation.
type Backend interface {
	// GetStatus returns a key manager status by key manager ID.
	GetStatus(context.Context, signature.PublicKey) (*Status, error)

	// GetStatuses returns all currently tracked key manager statuses.
	GetStatuses(context.Context) ([]*Status, error)

	// WatchStatuses returns a channel that produces a stream of messages
	// containing the key manager statuses as it changes over time.
	//
	// Upon subscription the current status is sent immediately.
	WatchStatuses() (<-chan *Status, *pubsub.Subscription)
}

// InitResponse is the initialization RPC response, returned as part of a
// SignedInitResponse from the key manager enclave.
type InitResponse struct {
	IsSecure bool   `codec:"is_secure"`
	Checksum []byte `codec:"checksum"`
}

// SignedInitResponse is the signed initialization RPC response, returned
// from the key manager enclave.
type SignedInitResponse struct {
	InitResponse InitResponse `codec:"init_response"`
	Signature    []byte       `codec:"signature"`
}

func (r *SignedInitResponse) Verify(pk signature.PublicKey) error {
	raw := cbor.Marshal(r.InitResponse)
	if !pk.Verify(initResponseContext, raw, r.Signature) {
		return errors.New("keymanager: invalid initialization response signature")
	}
	return nil
}

// VerifyExtraInfo verifies and parses the per-node + per-runtime ExtraInfo
// blob for a key manager.
func VerifyExtraInfo(rt *registry.Runtime, nodeRt *node.Runtime) (*InitResponse, error) {
	var (
		hw  node.TEEHardware
		rak signature.PublicKey
	)
	if nodeRt.Capabilities.TEE == nil || nodeRt.Capabilities.TEE.Hardware == node.TEEHardwareInvalid {
		hw = node.TEEHardwareInvalid
		rak = TestPublicKey
	} else {
		// TODO: MRENCLAVE/MRSIGNER.
		hw = nodeRt.Capabilities.TEE.Hardware
		rak = nodeRt.Capabilities.TEE.RAK
	}
	if hw != rt.TEEHardware {
		return nil, errors.New("keymanger: TEEHardware mismatch")
	}

	var untrustedSignedInitResponse SignedInitResponse
	if err := cbor.Unmarshal(nodeRt.ExtraInfo, &untrustedSignedInitResponse); err != nil {
		return nil, err
	}
	if err := untrustedSignedInitResponse.Verify(rak); err != nil {
		return nil, err
	}
	return &untrustedSignedInitResponse.InitResponse, nil
}

// Genesis is the key manager management genesis state.
type Genesis struct {
	Statuses []*Status `codec:"statuses,omit_empty"`
}

func init() {
	// Old `INSECURE_SIGNING_KEY_PKCS8`.
	var oldTestKey signature.PublicKey
	_ = oldTestKey.UnmarshalHex("9d41a874b80e39a40c9644e964f0e4f967100c91654bfd7666435fe906af060f")
	signature.RegisterTestPublicKey(oldTestKey)

	// Register all the seed derived SGX key manger test keys.
	testPrivateKey := signature.NewTestPrivateKey("ekiden test key manager RAK seed")
	TestPublicKey = testPrivateKey.Public()
}
