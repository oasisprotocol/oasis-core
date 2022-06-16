package interop

import (
	"context"
	"fmt"
	"net"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

var (
	entitySigner = memorySigner.NewTestSigner("consensus/tendermint/apps/registry/state: entity signer")
	nodeSigner1  = memorySigner.NewTestSigner("consensus/tendermint/apps/registry/state/interop: node signer 1")
	nodeSigner2  = memorySigner.NewTestSigner("consensus/tendermint/apps/registry/state/interop: node signer 2")
)

// InitializeTestRegistryState must be kept in sync with tests in runtimes/consensus/state/registry.rs.
func InitializeTestRegistryState(ctx context.Context, mkvs mkvs.Tree) error {
	state := registryState.NewMutableState(mkvs)

	var runtimeID common.Namespace
	if err := runtimeID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000010"); err != nil {
		return err
	}
	var runtimeID2 common.Namespace
	if err := runtimeID2.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000011"); err != nil {
		return err
	}
	// Populate nodes.
	for _, fix := range []struct {
		nodeSigner signature.Signer
		node       *node.Node
	}{
		{
			nodeSigner: nodeSigner1,
			node: &node.Node{
				Versioned:  cbor.NewVersioned(node.LatestNodeDescriptorVersion),
				ID:         nodeSigner1.Public(),
				EntityID:   entitySigner.Public(),
				Expiration: 32,
			},
		},
		{
			nodeSigner: nodeSigner2,
			node: &node.Node{
				Versioned:  cbor.NewVersioned(node.LatestNodeDescriptorVersion),
				ID:         nodeSigner2.Public(),
				EntityID:   entitySigner.Public(),
				Expiration: 32,
				TLS: node.TLSInfo{
					PubKey:     signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0"),
					NextPubKey: signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1"),
					Addresses: []node.TLSAddress{
						{
							PubKey: signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff2"),
							Address: node.Address{
								IP:   net.IPv4(127, 0, 0, 1),
								Port: 1111,
							},
						},
					},
				},
				P2P: node.P2PInfo{
					ID:        signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3"),
					Addresses: []node.Address{},
				},
				Consensus: node.ConsensusInfo{
					ID:        signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4"),
					Addresses: []node.ConsensusAddress{},
				},
				VRF: &node.VRFInfo{
					ID: signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5"),
				},
				Runtimes: []*node.Runtime{
					{
						ID:      runtimeID,
						Version: version.FromU64(321),
					},
					{
						ID:      runtimeID2,
						Version: version.FromU64(123),
						Capabilities: node.Capabilities{TEE: &node.CapabilityTEE{
							Hardware:    node.TEEHardwareIntelSGX,
							RAK:         signature.NewPublicKey("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8"),
							Attestation: []byte{0, 1, 2, 3, 4, 5},
						}},
						ExtraInfo: []byte{5, 3, 2, 1},
					},
				},
			},
		},
	} {
		signed, err := node.MultiSignNode([]signature.Signer{fix.nodeSigner}, registry.RegisterNodeSignatureContext, fix.node)
		if err != nil {
			return fmt.Errorf("signing node fixture: %w", err)
		}
		if err = state.SetNode(ctx, nil, fix.node, signed); err != nil {
			return fmt.Errorf("setting node: %w", err)
		}
	}

	// Populate runtimes.
	for _, fix := range []struct {
		rt        *registry.Runtime
		suspended bool
	}{
		{
			&registry.Runtime{
				Versioned:   cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
				ID:          runtimeID,
				EntityID:    entitySigner.Public(),
				Kind:        registry.KindCompute,
				TEEHardware: node.TEEHardwareInvalid,
				AdmissionPolicy: registry.RuntimeAdmissionPolicy{
					AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
				},
				Deployments: []*registry.VersionInfo{
					{
						Version:   version.FromU64(321),
						ValidFrom: 42,
					},
					{
						Version:   version.FromU64(320),
						ValidFrom: 10,
					},
				},
			},
			false,
		},
		{
			&registry.Runtime{
				Versioned:   cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
				ID:          runtimeID2,
				EntityID:    entitySigner.Public(),
				Kind:        registry.KindCompute,
				TEEHardware: node.TEEHardwareIntelSGX,
				AdmissionPolicy: registry.RuntimeAdmissionPolicy{
					AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
				},
				Deployments: []*registry.VersionInfo{
					{
						Version:   version.FromU64(123),
						ValidFrom: 42,
						TEE:       []byte{1, 2, 3, 4, 5},
					},
					{
						Version:   version.FromU64(120),
						ValidFrom: 10,
						TEE:       []byte{5, 4, 3, 2, 1},
					},
				},
			},
			true,
		},
	} {
		if err := state.SetRuntime(ctx, fix.rt, fix.suspended); err != nil {
			return fmt.Errorf("setting runtime: %w", err)
		}
	}

	return nil
}
