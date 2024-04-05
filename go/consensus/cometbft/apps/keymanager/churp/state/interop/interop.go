package interop

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	churpState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/churp/state"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

// InitializeTestKeyManagerSecretsState must be kept in sync with tests in runtimes/consensus/state/keymanager/churp.rs.
func InitializeTestKeyManagerSecretsState(ctx context.Context, mkvs mkvs.Tree) error {
	state := churpState.NewMutableState(mkvs)

	// One runtime.
	var runtime common.Namespace
	if err := runtime.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000"); err != nil {
		return err
	}

	// Two enclave identities.
	var enclave1, enclave2 sgx.EnclaveIdentity
	if err := enclave1.MrEnclave.UnmarshalHex("c9a589851b1f35627177fd70378ed778170f737611e4dfbf0b6d25bdff55b474"); err != nil {
		return err
	}
	if err := enclave1.MrSigner.UnmarshalHex("7d310664780931ae103ab30a90171c201af385a72757bb4683578fdebde9adf5"); err != nil {
		return err
	}
	if err := enclave2.MrEnclave.UnmarshalHex("756eaf76f5482c5345808b1eaccdd5c60f864bb2aa2d2b870df00ce435af4e23"); err != nil {
		return err
	}
	if err := enclave2.MrSigner.UnmarshalHex("3597a2ff0743016f28e5d7e129304ee1c43dbdae3dba94e19cee3549038a5a32"); err != nil {
		return err
	}

	// CHURP identity.
	identity := churp.Identity{
		ID:        1,
		RuntimeID: runtime,
	}

	// Signed policy.
	policy := churp.PolicySGX{
		Identity: identity,
		Serial:   6,
		MayShare: []sgx.EnclaveIdentity{enclave1},
		MayJoin:  []sgx.EnclaveIdentity{enclave2},
	}
	sigPolicy := churp.SignedPolicySGX{
		Policy:     policy,
		Signatures: []signature.Signature{},
	}

	// Two signers.
	signers := []signature.Signer{
		memorySigner.NewTestSigner("first signer"),
		memorySigner.NewTestSigner("second signer"),
	}

	for _, signer := range signers {
		sig, err := signature.Sign(signer, secrets.PolicySGXSignatureContext, cbor.Marshal(policy))
		if err != nil {
			return fmt.Errorf("failed to sign policy: %w", err)
		}
		sigPolicy.Signatures = append(sigPolicy.Signatures, *sig)
	}

	// Random checksum.
	var checksum hash.Hash
	if err := checksum.UnmarshalHex("1bff211fae98c88ba82388ae954b88a71d3bbe327e162e9fa711fe7a1b759c3e"); err != nil {
		return err
	}

	// Committee.
	committee := []signature.PublicKey{signers[0].Public(), signers[1].Public()}

	// Applications.
	applications := map[signature.PublicKey]churp.Application{
		signers[0].Public(): {
			Checksum:      checksum,
			Reconstructed: false,
		},
		signers[1].Public(): {
			Checksum:      checksum,
			Reconstructed: true,
		},
	}

	// Empty status.
	var status churp.Status
	if err := state.SetStatus(ctx, &status); err != nil {
		return fmt.Errorf("failed to set key CHURP status: %w", err)
	}

	// Non-empty status.
	status = churp.Status{
		Identity:        identity,
		GroupID:         churp.EccNistP384,
		Threshold:       2,
		HandoffInterval: 3,
		Policy:          sigPolicy,
		Handoff:         4,
		Checksum:        &checksum,
		Committee:       committee,
		NextHandoff:     5,
		NextChecksum:    &checksum,
		Applications:    applications,
	}

	if err := state.SetStatus(ctx, &status); err != nil {
		return fmt.Errorf("failed to set key CHURP status: %w", err)
	}

	return nil
}
