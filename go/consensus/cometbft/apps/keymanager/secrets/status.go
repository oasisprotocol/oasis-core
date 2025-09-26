package secrets

import (
	"bytes"
	"fmt"
	"time"

	"golang.org/x/crypto/sha3"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/common"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

// minProposalReplicationPercent is the minimum percentage of enclaves in the key manager committee
// that must replicate the proposal for the next master secret before it is accepted.
const minProposalReplicationPercent = 66

var emptyHashSha3 = sha3.Sum256(nil)

func generateStatus( // nolint: gocyclo
	ctx *tmapi.Context,
	kmrt *registry.Runtime,
	oldStatus *secrets.Status,
	secret *secrets.SignedEncryptedMasterSecret,
	nodes []*node.Node,
	params *registry.ConsensusParameters,
	epoch beacon.EpochTime,
) *secrets.Status {
	status := &secrets.Status{
		ID:            kmrt.ID,
		IsInitialized: oldStatus.IsInitialized,
		IsSecure:      oldStatus.IsSecure,
		Generation:    oldStatus.Generation,
		RotationEpoch: oldStatus.RotationEpoch,
		Checksum:      oldStatus.Checksum,
		Policy:        oldStatus.Policy,
	}

	// Transition to the scheduled policy.
	if oldStatus.NextPolicy != nil {
		status.Policy = oldStatus.NextPolicy
	}

	// Data needed to count the nodes that have replicated the proposal for the next master secret.
	var (
		nextGeneration uint64
		nextChecksum   []byte
		nextRSK        *signature.PublicKey
		updatedNodes   []signature.PublicKey
	)
	nextGeneration = status.NextGeneration()
	if secret != nil && secret.Secret.Generation == nextGeneration && secret.Secret.Epoch == epoch {
		nextChecksum = secret.Secret.Secret.Checksum
	}

	// Compute the policy hash to reject nodes that are not up-to-date.
	var rawPolicy []byte
	if status.Policy != nil {
		rawPolicy = cbor.Marshal(status.Policy)
	}
	policyHash := sha3.Sum256(rawPolicy)

	ts := ctx.Now()
	height := uint64(ctx.LastHeight())

	// Construct a key manager committee. A node is added to the committee if it supports
	// at least one version of the key manager runtime and if all supported versions conform
	// to the key manager status fields.
nextNode:
	for _, n := range nodes {
		if n.IsExpired(epoch) {
			continue
		}
		if !n.HasRoles(node.RoleKeyManager) {
			continue
		}

		secretReplicated := true
		isInitialized := status.IsInitialized
		isSecure := status.IsSecure
		RSK := status.RSK
		nRSK := nextRSK

		var numVersions int
		for _, nodeRt := range n.Runtimes {
			if !nodeRt.ID.Equal(&kmrt.ID) {
				continue
			}

			vars := []any{
				"id", kmrt.ID,
				"node_id", n.ID,
				"version", nodeRt.Version,
			}

			var teeOk bool
			if nodeRt.Capabilities.TEE == nil {
				teeOk = kmrt.TEEHardware == node.TEEHardwareInvalid
			} else {
				teeOk = kmrt.TEEHardware == nodeRt.Capabilities.TEE.Hardware
			}
			if !teeOk {
				ctx.Logger().Error("TEE hardware mismatch", vars...)
				continue nextNode
			}

			initResponse, err := VerifyExtraInfo(ctx.Logger(), n.ID, kmrt, nodeRt, ts, height, params)
			if err != nil {
				ctx.Logger().Error("failed to validate ExtraInfo", append(vars, "err", err)...)
				continue nextNode
			}

			// Skip nodes with mismatched policy.
			var nodePolicyHash [secrets.ChecksumSize]byte
			switch len(initResponse.PolicyChecksum) {
			case 0:
				nodePolicyHash = emptyHashSha3
			case secrets.ChecksumSize:
				copy(nodePolicyHash[:], initResponse.PolicyChecksum)
			default:
				ctx.Logger().Error("failed to parse policy checksum", append(vars, "err", err)...)
				continue nextNode
			}
			if policyHash != nodePolicyHash {
				ctx.Logger().Error("Policy checksum mismatch for runtime", vars...)
				continue nextNode
			}

			// Set immutable status fields that cannot change after initialization.
			if !isInitialized {
				// The first version gets to be the source of truth.
				isInitialized = true
				isSecure = initResponse.IsSecure
			}

			// Skip nodes with mismatched status fields.
			if initResponse.IsSecure != isSecure {
				ctx.Logger().Error("Security status mismatch for runtime", vars...)
				continue nextNode
			}

			// Skip nodes with mismatched checksum.
			// Note that a node needs to register with an empty checksum if no master secrets
			// have been generated so far. Otherwise, if secrets have been generated, the node
			// needs to register with a checksum computed over all the secrets generated so far
			// since the key manager's checksum is updated after every master secret rotation.
			if !bytes.Equal(initResponse.Checksum, status.Checksum) {
				ctx.Logger().Error("Checksum mismatch for runtime", vars...)
				continue nextNode
			}

			// Update mutable status fields that can change on epoch transitions.
			if RSK == nil {
				// The first version with non-nil runtime signing key gets to be the source of truth.
				RSK = initResponse.RSK
			}

			// Skip nodes with mismatched runtime signing key.
			// For backward compatibility we always allow nodes without runtime signing key.
			if initResponse.RSK != nil && !initResponse.RSK.Equal(*RSK) {
				ctx.Logger().Error("Runtime signing key mismatch for runtime", vars)
				continue nextNode
			}

			// Check if all versions have replicated the last master secret,
			// derived the same RSK and are ready to move to the next generation.
			if !bytes.Equal(initResponse.NextChecksum, nextChecksum) {
				secretReplicated = false
			}
			if nRSK == nil {
				nRSK = initResponse.NextRSK
			}
			if initResponse.NextRSK != nil && !initResponse.NextRSK.Equal(*nRSK) {
				secretReplicated = false
			}

			numVersions++
		}

		if numVersions == 0 {
			continue
		}
		if !isInitialized {
			panic("the key manager must be initialized")
		}
		if secretReplicated {
			nextRSK = nRSK
			updatedNodes = append(updatedNodes, n.ID)
		}

		// If the key manager is not initialized, the first verified node gets to be the source
		// of truth, every other node will sync off it.
		if !status.IsInitialized {
			status.IsInitialized = true
			status.IsSecure = isSecure
		}
		status.RSK = RSK
		status.Nodes = append(status.Nodes, n.ID)
	}

	// Accept the proposal if the majority of the nodes have replicated
	// the proposal for the next master secret.
	if numNodes := len(status.Nodes); numNodes > 0 && nextChecksum != nil {
		percent := len(updatedNodes) * 100 / numNodes
		if percent >= minProposalReplicationPercent {
			status.Generation = nextGeneration
			status.RotationEpoch = epoch
			status.Checksum = nextChecksum
			status.RSK = nextRSK
			status.Nodes = updatedNodes
		}
	}

	return status
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
) (*secrets.InitResponse, error) {
	if err := registry.VerifyNodeRuntimeEnclaveIDs(logger, nodeID, nodeRt, rt, params.TEEFeatures, ts, height); err != nil {
		return nil, err
	}
	if nodeRt.ExtraInfo == nil {
		return nil, fmt.Errorf("keymanager: missing ExtraInfo")
	}

	rak, err := common.RuntimeAttestationKey(nodeRt, rt)
	if err != nil {
		return nil, err
	}

	var untrustedSignedInitResponse secrets.SignedInitResponse
	if err := cbor.Unmarshal(nodeRt.ExtraInfo, &untrustedSignedInitResponse); err != nil {
		return nil, err
	}
	if err := untrustedSignedInitResponse.Verify(*rak); err != nil {
		return nil, err
	}
	return &untrustedSignedInitResponse.InitResponse, nil
}
