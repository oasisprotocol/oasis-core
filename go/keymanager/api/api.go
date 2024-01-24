// Package api implements the key manager management API and common data types.
package api

import (
	"context"
	"crypto/sha512"
	"fmt"
	"time"

	"github.com/oasisprotocol/curve25519-voi/primitives/x25519"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
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

	// KeyPairIDSize is the size of a key pair ID in bytes.
	KeyPairIDSize = 32
)

var (
	// ErrInvalidArgument is the error returned on malformed arguments.
	ErrInvalidArgument = errors.New(ModuleName, 1, "keymanager: invalid argument")

	// ErrNoSuchStatus is the error returned when a key manager status does not
	// exist.
	ErrNoSuchStatus = errors.New(ModuleName, 2, "keymanager: no such status")

	// ErrNoSuchMasterSecret is the error returned when a key manager master secret does not exist.
	ErrNoSuchMasterSecret = errors.New(ModuleName, 3, "keymanager: no such master secret")

	// ErrNoSuchEphemeralSecret is the error returned when a key manager ephemeral secret
	// does not exist.
	ErrNoSuchEphemeralSecret = errors.New(ModuleName, 4, "keymanager: no such ephemeral secret")

	// MethodUpdatePolicy is the method name for policy updates.
	MethodUpdatePolicy = transaction.NewMethodName(ModuleName, "UpdatePolicy", SignedPolicySGX{})

	// MethodPublishMasterSecret is the method name for publishing master secret.
	MethodPublishMasterSecret = transaction.NewMethodName(ModuleName, "PublishMasterSecret", SignedEncryptedMasterSecret{})

	// MethodPublishEphemeralSecret is the method name for publishing ephemeral secret.
	MethodPublishEphemeralSecret = transaction.NewMethodName(ModuleName, "PublishEphemeralSecret", SignedEncryptedEphemeralSecret{})

	// InsecureRAK is the insecure hardcoded key manager public key, used
	// in insecure builds when a RAK is unavailable.
	InsecureRAK signature.PublicKey

	// InsecureREK is the insecure hardcoded key manager public key, used
	// in insecure builds when a REK is unavailable.
	InsecureREK x25519.PublicKey

	// TestSigners contains a list of signers with corresponding test keys, used
	// in insecure builds when a RAK is unavailable.
	TestSigners []signature.Signer

	// Methods is the list of all methods supported by the key manager backend.
	Methods = []transaction.MethodName{
		MethodUpdatePolicy,
		MethodPublishMasterSecret,
		MethodPublishEphemeralSecret,
	}

	// RPCMethodConnect is the name of the method used to establish a Noise session.
	RPCMethodConnect = ""

	// RPCMethodInit is the name of the `init` method.
	RPCMethodInit = "init"

	// RPCMethodGetOrCreateKeys is the name of the `get_or_create_keys` method.
	RPCMethodGetOrCreateKeys = "get_or_create_keys"

	// RPCMethodGetPublicKey is the name of the `get_public_key` method.
	RPCMethodGetPublicKey = "get_public_key"

	// RPCMethodGetOrCreateEphemeralKeys is the name of the `get_or_create_ephemeral_keys` method.
	RPCMethodGetOrCreateEphemeralKeys = "get_or_create_ephemeral_keys"

	// RPCMethodGetPublicEphemeralKey is the name of the `get_public_ephemeral_key` method.
	RPCMethodGetPublicEphemeralKey = "get_public_ephemeral_key" // #nosec G101

	// RPCMethodReplicateMasterSecret is the name of the `replicate_master_secret` method.
	RPCMethodReplicateMasterSecret = "replicate_master_secret"

	// RPCMethodReplicateEphemeralSecret is the name of the `replicate_ephemeral_secret` method.
	RPCMethodReplicateEphemeralSecret = "replicate_ephemeral_secret"

	// RPCMethodGenerateMasterSecret is the name of the `generate_master_secret` RPC method.
	RPCMethodGenerateMasterSecret = "generate_master_secret"

	// RPCMethodGenerateEphemeralSecret is the name of the `generate_ephemeral_secret` RPC method.
	RPCMethodGenerateEphemeralSecret = "generate_ephemeral_secret"

	// RPCMethodLoadMasterSecret is the name of the `load_master_secret` RPC method.
	RPCMethodLoadMasterSecret = "load_master_secret"

	// RPCMethodLoadEphemeralSecret is the name of the `load_ephemeral_secret` RPC method.
	RPCMethodLoadEphemeralSecret = "load_ephemeral_secret"

	// initResponseSignatureContext is the context used to sign key manager init responses.
	initResponseSignatureContext = signature.NewContext("oasis-core/keymanager: init response")
)

const (
	// GasOpUpdatePolicy is the gas operation identifier for policy updates
	// costs.
	GasOpUpdatePolicy transaction.Op = "update_policy"
	// GasOpPublishMasterSecret is the gas operation identifier for publishing
	// key manager master secret.
	GasOpPublishMasterSecret transaction.Op = "publish_master_secret"
	// GasOpPublishEphemeralSecret is the gas operation identifier for publishing
	// key manager ephemeral secret.
	GasOpPublishEphemeralSecret transaction.Op = "publish_ephemeral_secret"
)

// XXX: Define reasonable default gas costs.

// DefaultGasCosts are the "default" gas costs for operations.
var DefaultGasCosts = transaction.Costs{
	GasOpUpdatePolicy:           1000,
	GasOpPublishMasterSecret:    1000,
	GasOpPublishEphemeralSecret: 1000,
}

// KeyPairID is a 256-bit key pair identifier.
type KeyPairID [KeyPairIDSize]byte

// Status is the current key manager status.
type Status struct {
	// ID is the runtime ID of the key manager.
	ID common.Namespace `json:"id"`

	// IsInitialized is true iff the key manager is done initializing.
	IsInitialized bool `json:"is_initialized"`

	// IsSecure is true iff the key manager is secure.
	IsSecure bool `json:"is_secure"`

	// Generation is the generation of the latest master secret.
	Generation uint64 `json:"generation,omitempty"`

	// RotationEpoch is the epoch of the last master secret rotation.
	RotationEpoch beacon.EpochTime `json:"rotation_epoch,omitempty"`

	// Checksum is the key manager master secret verification checksum.
	Checksum []byte `json:"checksum"`

	// Nodes is the list of currently active key manager node IDs.
	Nodes []signature.PublicKey `json:"nodes"`

	// Policy is the key manager policy.
	Policy *SignedPolicySGX `json:"policy"`

	// RSK is the runtime signing key of the key manager.
	RSK *signature.PublicKey `json:"rsk,omitempty"`
}

// NextGeneration returns the generation of the next master secret.
func (s *Status) NextGeneration() uint64 {
	if len(s.Checksum) == 0 {
		return 0
	}
	return s.Generation + 1
}

// VerifyRotationEpoch verifies if rotation can be performed in the given epoch.
func (s *Status) VerifyRotationEpoch(epoch beacon.EpochTime) error {
	if nextGen := s.NextGeneration(); nextGen == 0 {
		return nil
	}

	// By default, rotation is disabled unless specified in the policy.
	var rotationInterval beacon.EpochTime
	if s.Policy != nil {
		rotationInterval = s.Policy.Policy.MasterSecretRotationInterval
	}

	// Reject if rotation is disabled.
	if rotationInterval == 0 {
		return fmt.Errorf("master secret rotation disabled")
	}

	// Reject if the rotation period has not expired.
	rotationEpoch := s.RotationEpoch + rotationInterval
	if epoch < rotationEpoch {
		return fmt.Errorf("master secret rotation interval has not yet expired")
	}

	return nil
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

	// GetMasterSecret returns the key manager master secret.
	GetMasterSecret(context.Context, *registry.NamespaceQuery) (*SignedEncryptedMasterSecret, error)

	// WatchMasterSecrets returns a channel that produces a stream of master secrets.
	WatchMasterSecrets() (<-chan *SignedEncryptedMasterSecret, *pubsub.Subscription)

	// GetEphemeralSecret returns the key manager ephemeral secret.
	GetEphemeralSecret(context.Context, *registry.NamespaceQuery) (*SignedEncryptedEphemeralSecret, error)

	// WatchEphemeralSecrets returns a channel that produces a stream of ephemeral secrets.
	WatchEphemeralSecrets() (<-chan *SignedEncryptedEphemeralSecret, *pubsub.Subscription)
}

// NewUpdatePolicyTx creates a new policy update transaction.
func NewUpdatePolicyTx(nonce uint64, fee *transaction.Fee, sigPol *SignedPolicySGX) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodUpdatePolicy, sigPol)
}

// NewPublishMasterSecretTx creates a new publish master secret transaction.
func NewPublishMasterSecretTx(nonce uint64, fee *transaction.Fee, sigSec *SignedEncryptedMasterSecret) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodPublishMasterSecret, sigSec)
}

// NewPublishEphemeralSecretTx creates a new publish ephemeral secret transaction.
func NewPublishEphemeralSecretTx(nonce uint64, fee *transaction.Fee, sigSec *SignedEncryptedEphemeralSecret) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodPublishEphemeralSecret, sigSec)
}

// InitRequest is the initialization RPC request, sent to the key manager
// enclave.
type InitRequest struct {
	Status Status `json:"status,omitempty"`
}

// InitResponse is the initialization RPC response, returned as part of a
// SignedInitResponse from the key manager enclave.
type InitResponse struct {
	IsSecure       bool                 `json:"is_secure"`
	Checksum       []byte               `json:"checksum"`
	NextChecksum   []byte               `json:"next_checksum,omitempty"`
	PolicyChecksum []byte               `json:"policy_checksum"`
	RSK            *signature.PublicKey `json:"rsk,omitempty"`
	NextRSK        *signature.PublicKey `json:"next_rsk,omitempty"`
}

// SignedInitResponse is the signed initialization RPC response, returned
// from the key manager enclave.
type SignedInitResponse struct {
	InitResponse InitResponse `json:"init_response"`
	Signature    []byte       `json:"signature"`
}

// Verify verifies the signature of the init response using the given key.
func (r *SignedInitResponse) Verify(pk signature.PublicKey) error {
	raw := cbor.Marshal(r.InitResponse)
	if !pk.Verify(initResponseSignatureContext, raw, r.Signature) {
		return fmt.Errorf("keymanager: invalid initialization response signature")
	}
	return nil
}

// SignInitResponse signs the given init response.
func SignInitResponse(signer signature.Signer, response *InitResponse) (*SignedInitResponse, error) {
	sig, err := signer.ContextSign(initResponseSignatureContext, cbor.Marshal(response))
	if err != nil {
		return nil, err
	}
	return &SignedInitResponse{
		InitResponse: *response,
		Signature:    sig,
	}, nil
}

// LongTermKeyRequest is the long-term key RPC request, sent to the key manager
// enclave.
type LongTermKeyRequest struct {
	Height     *uint64          `json:"height"`
	ID         common.Namespace `json:"runtime_id"`
	KeyPairID  KeyPairID        `json:"key_pair_id"`
	Generation uint64           `json:"generation"`
}

// EphemeralKeyRequest is the ephemeral key RPC request, sent to the key manager
// enclave.
type EphemeralKeyRequest struct {
	Height    *uint64          `json:"height"`
	ID        common.Namespace `json:"runtime_id"`
	KeyPairID KeyPairID        `json:"key_pair_id"`
	Epoch     beacon.EpochTime `json:"epoch"`
}

// SignedPublicKey is the RPC response, returned as part of
// an EphemeralKeyRequest from the key manager enclave.
type SignedPublicKey struct {
	Key        x25519.PublicKey       `json:"key"`
	Checksum   []byte                 `json:"checksum"`
	Signature  signature.RawSignature `json:"signature"`
	Expiration *beacon.EpochTime      `json:"expiration,omitempty"`
}

// GenerateMasterSecretRequest is the generate master secret RPC request,
// sent to the key manager enclave.
type GenerateMasterSecretRequest struct {
	Generation uint64           `json:"generation"`
	Epoch      beacon.EpochTime `json:"epoch"`
}

// GenerateMasterSecretResponse is the RPC response, returned as part of
// a GenerateMasterSecretRequest from the key manager enclave.
type GenerateMasterSecretResponse struct {
	SignedSecret SignedEncryptedMasterSecret `json:"signed_secret"`
}

// GenerateEphemeralSecretRequest is the generate ephemeral secret RPC request,
// sent to the key manager enclave.
type GenerateEphemeralSecretRequest struct {
	Epoch beacon.EpochTime `json:"epoch"`
}

// GenerateEphemeralSecretResponse is the RPC response, returned as part of
// a GenerateEphemeralSecretRequest from the key manager enclave.
type GenerateEphemeralSecretResponse struct {
	SignedSecret SignedEncryptedEphemeralSecret `json:"signed_secret"`
}

// LoadMasterSecretRequest is the load master secret RPC request,
// sent to the key manager enclave.
type LoadMasterSecretRequest struct {
	SignedSecret SignedEncryptedMasterSecret `json:"signed_secret"`
}

// LoadEphemeralSecretRequest is the load ephemeral secret RPC request,
// sent to the key manager enclave.
type LoadEphemeralSecretRequest struct {
	SignedSecret SignedEncryptedEphemeralSecret `json:"signed_secret"`
}

// VerifyExtraInfo verifies and parses the per-node + per-runtime ExtraInfo
// blob for a key manager.
func VerifyExtraInfo(
	logger *logging.Logger,
	nodeID signature.PublicKey,
	rt *registry.Runtime,
	nodeRt *node.Runtime,
	ts time.Time,
	height uint64,
	params *registry.ConsensusParameters,
) (*InitResponse, error) {
	var (
		hw  node.TEEHardware
		rak signature.PublicKey
	)
	if nodeRt.Capabilities.TEE == nil || nodeRt.Capabilities.TEE.Hardware == node.TEEHardwareInvalid {
		hw = node.TEEHardwareInvalid
		rak = InsecureRAK
	} else {
		hw = nodeRt.Capabilities.TEE.Hardware
		rak = nodeRt.Capabilities.TEE.RAK
	}
	if hw != rt.TEEHardware {
		return nil, fmt.Errorf("keymanager: TEEHardware mismatch")
	} else if err := registry.VerifyNodeRuntimeEnclaveIDs(logger, nodeID, nodeRt, rt, params.TEEFeatures, ts, height); err != nil {
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
	// Parameters are the key manager consensus parameters.
	Parameters ConsensusParameters `json:"params"`

	Statuses []*Status `json:"statuses,omitempty"`
}

// ConsensusParameters are the key manager consensus parameters.
type ConsensusParameters struct {
	GasCosts transaction.Costs `json:"gas_costs,omitempty"`
}

// ConsensusParameterChanges are allowed key manager consensus parameter changes.
type ConsensusParameterChanges struct {
	// GasCosts are the new gas costs.
	GasCosts transaction.Costs `json:"gas_costs,omitempty"`
}

// Apply applies changes to the given consensus parameters.
func (c *ConsensusParameterChanges) Apply(params *ConsensusParameters) error {
	if c.GasCosts != nil {
		params.GasCosts = c.GasCosts
	}
	return nil
}

// StatusUpdateEvent is the keymanager status update event.
type StatusUpdateEvent struct {
	Statuses []*Status
}

// EventKind returns a string representation of this event's kind.
func (ev *StatusUpdateEvent) EventKind() string {
	return "status"
}

// MasterSecretPublishedEvent is the key manager master secret published event.
type MasterSecretPublishedEvent struct {
	Secret *SignedEncryptedMasterSecret
}

// EventKind returns a string representation of this event's kind.
func (ev *MasterSecretPublishedEvent) EventKind() string {
	return "master_secret"
}

// EphemeralSecretPublishedEvent is the key manager ephemeral secret published event.
type EphemeralSecretPublishedEvent struct {
	Secret *SignedEncryptedEphemeralSecret
}

// EventKind returns a string representation of this event's kind.
func (ev *EphemeralSecretPublishedEvent) EventKind() string {
	return "ephemeral_secret"
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
			InsecureRAK = tmpSigner.Public()
		}
	}

	rek := x25519.PrivateKey(sha512.Sum512_256([]byte("ekiden test key manager REK seed")))
	InsecureREK = *rek.Public()
}
