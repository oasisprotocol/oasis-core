package interop

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	kmState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/keymanager/state"
	kmApi "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

// InitializeTestKeyManagerState must be kept in sync with tests in runtimes/consensus/state/keymanager.rs.
func InitializeTestKeyManagerState(ctx context.Context, mkvs mkvs.Tree) error {
	state := kmState.NewMutableState(mkvs)

	// One runtime, two key manager runtimes.
	var runtime, keymanager1, keymanager2 common.Namespace
	if err := runtime.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000"); err != nil {
		return err
	}
	if err := keymanager1.UnmarshalHex("c000000000000000fffffffffffffffffffffffffffffffffffffffffffffffe"); err != nil {
		return err
	}
	if err := keymanager2.UnmarshalHex("c000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff"); err != nil {
		return err
	}

	// Three enclave identities.
	var runtimeEnclave, keymanagerEnclave1, keymanagerEnclave2 sgx.EnclaveIdentity
	if err := runtimeEnclave.MrEnclave.UnmarshalHex("18256f783c071521be2da041cd9347b5bdb5a8ef58fb34658571a6e14cf1fcb0"); err != nil {
		return err
	}
	if err := runtimeEnclave.MrSigner.UnmarshalHex("e48049d1de0eb333523991671a6c93b97dd65bcf09273d5b6bfe8262dc968ec7"); err != nil {
		return err
	}
	if err := keymanagerEnclave1.MrEnclave.UnmarshalHex("c9a589851b1f35627177fd70378ed778170f737611e4dfbf0b6d25bdff55b474"); err != nil {
		return err
	}
	if err := keymanagerEnclave1.MrSigner.UnmarshalHex("7d310664780931ae103ab30a90171c201af385a72757bb4683578fdebde9adf5"); err != nil {
		return err
	}
	if err := keymanagerEnclave2.MrEnclave.UnmarshalHex("756eaf76f5482c5345808b1eaccdd5c60f864bb2aa2d2b870df00ce435af4e23"); err != nil {
		return err
	}
	if err := keymanagerEnclave2.MrSigner.UnmarshalHex("3597a2ff0743016f28e5d7e129304ee1c43dbdae3dba94e19cee3549038a5a32"); err != nil {
		return err
	}

	// Signed policy.
	enclavePolicySGX := kmApi.EnclavePolicySGX{
		MayQuery: map[common.Namespace][]sgx.EnclaveIdentity{
			runtime: {
				runtimeEnclave,
			},
		},
		MayReplicate: []sgx.EnclaveIdentity{
			keymanagerEnclave2,
		},
	}
	policy := kmApi.PolicySGX{
		Serial: 1,
		ID:     keymanager2,
		Enclaves: map[sgx.EnclaveIdentity]*kmApi.EnclavePolicySGX{
			keymanagerEnclave1: &enclavePolicySGX,
		},
	}
	sigPolicy := kmApi.SignedPolicySGX{
		Policy:     policy,
		Signatures: []signature.Signature{},
	}

	// Two signers.
	signers := []signature.Signer{
		memorySigner.NewTestSigner("first signer"),
		memorySigner.NewTestSigner("second signer"),
	}

	for _, signer := range signers {
		sig, err := signature.Sign(signer, kmApi.PolicySGXSignatureContext, cbor.Marshal(policy))
		if err != nil {
			return fmt.Errorf("failed to sign policy: %w", err)
		}
		sigPolicy.Signatures = append(sigPolicy.Signatures, *sig)
	}

	// Random checksum.
	checksum, err := hex.DecodeString("1bff211fae98c88ba82388ae954b88a71d3bbe327e162e9fa711fe7a1b759c3e")
	if err != nil {
		return err
	}

	// Add two statuses.
	for _, status := range []*kmApi.Status{
		{
			ID:            keymanager1,
			IsInitialized: false,
			IsSecure:      false,
			Checksum:      nil,
			Nodes:         nil,
			Policy:        nil,
		},
		{
			ID:            keymanager2,
			IsInitialized: true,
			IsSecure:      true,
			Checksum:      checksum,
			Nodes: []signature.PublicKey{
				signers[0].Public(),
				signers[1].Public(),
			},
			Policy: &sigPolicy,
		},
	} {
		if err := state.SetStatus(ctx, status); err != nil {
			return fmt.Errorf("setting key manager status: %w", err)
		}
	}

	return nil
}
