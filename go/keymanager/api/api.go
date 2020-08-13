// Package api implements the key manager management API and common data types.
package api

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

const (
	// ModuleName is a unique module name for the keymanager module.
	ModuleName = "keymanager"

	// ChecksumSize is the length of checksum in bytes.
	ChecksumSize = 32

	// EnclaveRPCEndpoint is the name of the key manager EnclaveRPC endpoint.
	EnclaveRPCEndpoint = "key-manager"
)

var (
	// ErrNoSuchStatus is the error returned when a key manager status does not
	// exist.
	ErrNoSuchStatus = errors.New(ModuleName, 1, "keymanager: no such status")

	// MethodUpdatePolicy is the method name for policy updates.
	MethodUpdatePolicy = transaction.NewMethodName(ModuleName, "UpdatePolicy", SignedPolicySGX{})

	// TestPublicKey is the insecure hardcoded key manager public key, used
	// in insecure builds when a RAK is unavailable.
	TestPublicKey signature.PublicKey

	// TestSigners contains a list of signers with corresponding test keys, used
	// in insecure builds when a RAK is unavailable.
	TestSigners []signature.Signer

	// Methods is the list of all methods supported by the key manager backend.
	Methods = []transaction.MethodName{
		MethodUpdatePolicy,
	}

	initResponseContext = signature.NewContext("oasis-core/keymanager: init response")
)

// Status is the current key manager status.
type Status struct {
	// ID is the runtime ID of the key manager.
	ID common.Namespace `json:"id"`

	// IsInitialized is true iff the key manager is done initializing.
	IsInitialized bool `json:"is_initialized"`

	// IsSecure is true iff the key manager is secure.
	IsSecure bool `json:"is_secure"`

	// Checksum is the key manager master secret verification checksum.
	Checksum []byte `json:"checksum"`

	// Nodes is the list of currently active key manager node IDs.
	Nodes []signature.PublicKey `json:"nodes"`

	// Policy is the key manager policy.
	Policy *SignedPolicySGX `json:"policy"`
}

// Backend is a key manager management implementation.
type Backend interface {
	// GetStatus returns a key manager status by key manager ID.
	GetStatus(context.Context, *registry.NamespaceQuery) (*Status, error)

	// GetStatuses returns all currently tracked key manager statuses.
	GetStatuses(context.Context, int64) ([]*Status, error)

	// WatchStatuses returns a channel that produces a stream of messages
	// containing the key manager statuses as it changes over time.
	//
	// Upon subscription the current status is sent immediately.
	WatchStatuses() (<-chan *Status, *pubsub.Subscription)

	// StateToGenesis returns the genesis state at specified block height.
	StateToGenesis(context.Context, int64) (*Genesis, error)
}

// NewUpdatePolicyTx creates a new policy update transaction.
func NewUpdatePolicyTx(nonce uint64, fee *transaction.Fee, sigPol *SignedPolicySGX) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodUpdatePolicy, sigPol)
}

// InitResponse is the initialization RPC response, returned as part of a
// SignedInitResponse from the key manager enclave.
type InitResponse struct {
	IsSecure       bool   `json:"is_secure"`
	Checksum       []byte `json:"checksum"`
	PolicyChecksum []byte `json:"policy_checksum"`
}

// SignedInitResponse is the signed initialization RPC response, returned
// from the key manager enclave.
type SignedInitResponse struct {
	InitResponse InitResponse `json:"init_response"`
	Signature    []byte       `json:"signature"`
}

func (r *SignedInitResponse) Verify(pk signature.PublicKey) error {
	raw := cbor.Marshal(r.InitResponse)
	if !pk.Verify(initResponseContext, raw, r.Signature) {
		return fmt.Errorf("keymanager: invalid initialization response signature")
	}
	return nil
}

// VerifyExtraInfo verifies and parses the per-node + per-runtime ExtraInfo
// blob for a key manager.
func VerifyExtraInfo(logger *logging.Logger, rt *registry.Runtime, nodeRt *node.Runtime, ts time.Time) (*InitResponse, error) {
	var (
		hw  node.TEEHardware
		rak signature.PublicKey
	)
	if nodeRt.Capabilities.TEE == nil || nodeRt.Capabilities.TEE.Hardware == node.TEEHardwareInvalid {
		hw = node.TEEHardwareInvalid
		rak = TestPublicKey
	} else {
		hw = nodeRt.Capabilities.TEE.Hardware
		rak = nodeRt.Capabilities.TEE.RAK
	}
	if hw != rt.TEEHardware {
		return nil, fmt.Errorf("keymanager: TEEHardware mismatch")
	} else if err := registry.VerifyNodeRuntimeEnclaveIDs(logger, nodeRt, rt, ts); err != nil {
		return nil, err
	}
	if nodeRt.ExtraInfo == nil {
		return nil, fmt.Errorf("keymanager: missing ExtraInfo")
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
	Statuses []*Status `json:"statuses,omitempty"`
}

// SanityCheckStatuses examines the statuses table.
func SanityCheckStatuses(statuses []*Status) error {
	for _, status := range statuses {
		// Verify key manager runtime ID.
		if !status.ID.IsKeyManager() {
			return fmt.Errorf("keymanager: sanity check failed: key manager runtime ID %s is invalid", status.ID)
		}

		// Verify currently active key manager node IDs.
		for _, node := range status.Nodes {
			if !node.IsValid() {
				return fmt.Errorf("keymanager: sanity check failed: key manager node ID %s is invalid", node.String())
			}
		}

		// Verify SGX policy signatures if the policy exists.
		if status.Policy != nil {
			if err := SanityCheckSignedPolicySGX(nil, status.Policy); err != nil {
				return err
			}
		}
	}
	return nil
}

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck() error {
	err := SanityCheckStatuses(g.Statuses)
	if err != nil {
		return err
	}

	return nil
}

func init() {
	// Old `INSECURE_SIGNING_KEY_PKCS8`.
	var oldTestKey signature.PublicKey
	_ = oldTestKey.UnmarshalHex("9d41a874b80e39a40c9644e964f0e4f967100c91654bfd7666435fe906af060f")
	signature.RegisterTestPublicKey(oldTestKey)

	// Register all the seed derived SGX key manager test keys.
	for idx, v := range []string{
		"ekiden test key manager RAK seed", // DO NOT REORDER.
		"ekiden key manager test multisig key 0",
		"ekiden key manager test multisig key 1",
		"ekiden key manager test multisig key 2",
	} {
		tmpSigner := memorySigner.NewTestSigner(v)
		TestSigners = append(TestSigners, tmpSigner)

		if idx == 0 {
			TestPublicKey = tmpSigner.Public()
		}
	}
}
