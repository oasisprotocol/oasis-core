package node

import (
	"encoding/binary"
	"fmt"
	"slices"
	"time"

	"github.com/oasisprotocol/curve25519-voi/primitives/x25519"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/tuplehash"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/quote"
)

const (
	// LatestSGXConstraintsVersion is the latest SGX constraints structure version that should be
	// used for all new descriptors.
	LatestSGXConstraintsVersion = 1
)

var emptyFeatures TEEFeatures

// SGXConstraints are the Intel SGX TEE constraints.
type SGXConstraints struct {
	cbor.Versioned

	// Enclaves is the allowed MRENCLAVE/MRSIGNER pairs.
	Enclaves []sgx.EnclaveIdentity `json:"enclaves,omitempty"`

	// Policy is the quote policy that all attestations must satisfy.
	Policy *quote.Policy `json:"policy,omitempty"`

	// PerRolePolicy defines additional role specific quote policies.
	PerRolePolicy map[RolesMask]*quote.Policy `json:"per_role_policy,omitempty"`

	// MaxAttestationAge is the maximum attestation age (in blocks).
	MaxAttestationAge uint64 `json:"max_attestation_age,omitempty"`
}

// sgxConstraintsV0 are the version 0 Intel SGX TEE constraints which only supports IAS.
type sgxConstraintsV0 struct {
	Enclaves             []sgx.EnclaveIdentity       `json:"enclaves,omitempty"`
	AllowedQuoteStatuses []ias.ISVEnclaveQuoteStatus `json:"allowed_quote_statuses,omitempty"`
}

// UnmarshalCBOR is a custom deserializer that handles different structure versions.
func (sc *SGXConstraints) UnmarshalCBOR(data []byte) error {
	// Determine Entity structure version.
	v, err := cbor.GetVersion(data)
	if err != nil {
		v = 0 // Previous SGXConstraints structures were not versioned.
	}
	switch v {
	case 0:
		// Old version only supported the IAS-related constraints.
		var scv0 sgxConstraintsV0
		if err = cbor.Unmarshal(data, &scv0); err != nil {
			return err
		}

		// Convert into new format.
		sc.Versioned = cbor.NewVersioned(0)
		sc.Enclaves = scv0.Enclaves
		sc.Policy = &quote.Policy{
			IAS: &ias.QuotePolicy{
				AllowedQuoteStatuses: scv0.AllowedQuoteStatuses,
			},
		}
		return nil
	case 1:
		// New version, call the default unmarshaler.
		type scv1 SGXConstraints
		return cbor.Unmarshal(data, (*scv1)(sc))
	default:
		return fmt.Errorf("invalid SGX constraints version: %d", v)
	}
}

// MarshalCBOR is a custom serializer that handles different structure versions.
func (sc *SGXConstraints) MarshalCBOR() ([]byte, error) {
	switch sc.V {
	case 0:
		// Old version only supported the IAS-related constraints.
		scv0 := sgxConstraintsV0{
			Enclaves: sc.Enclaves,
		}
		if sc.Policy != nil && sc.Policy.IAS != nil {
			scv0.AllowedQuoteStatuses = sc.Policy.IAS.AllowedQuoteStatuses
		}
		return cbor.Marshal(scv0), nil
	default:
		type scv1 SGXConstraints
		return cbor.Marshal((*scv1)(sc)), nil
	}
}

// ValidateBasic performs basic structure validity checks.
func (sc *SGXConstraints) ValidateBasic(cfg *TEEFeatures, isFeatureVersion242 bool) error {
	if cfg == nil {
		cfg = &emptyFeatures
	}

	// Before the PCS feature only v0 of SGX constraints is supported.
	if !cfg.SGX.PCS && sc.V != 0 {
		return fmt.Errorf("unsupported SGX constraints version: %d", sc.V)
	}
	// Sanity check version (should never fail as deserialization already checks this).
	if sc.V > LatestSGXConstraintsVersion {
		return fmt.Errorf("unsupported SGX constraints version: %d", sc.V)
	}

	validatePolicy := func(policy *quote.Policy) error {
		// Check for TDX enablement.
		if !cfg.SGX.TDX && policy.PCS != nil && policy.PCS.TDX != nil {
			return fmt.Errorf("TDX policy not supported")
		}
		if err := policy.Validate(isFeatureVersion242); err != nil {
			return fmt.Errorf("invalid policy: %w", err)
		}
		return nil
	}

	// Check default policy.
	if sc.Policy != nil {
		if err := validatePolicy(sc.Policy); err != nil {
			return fmt.Errorf("invalid policy: %w", err)
		}
	}

	// Check per-role policies.
	if !isFeatureVersion242 && sc.PerRolePolicy != nil {
		return fmt.Errorf("per role policy should be empty")
	}
	for role, policy := range sc.PerRolePolicy {
		if !role.IsSingleRole() {
			return fmt.Errorf("per-role quote policies should have a single role")
		}
		if policy == nil {
			return fmt.Errorf("per-role policy should not be nil")
		}
		if err := validatePolicy(policy); err != nil {
			return fmt.Errorf("invalid policy (role: %s): %w", role, err)
		}
	}

	return nil
}

// ContainsEnclave returns true iff the allowed enclave list in SGX constraints contain the given
// enclave identity.
func (sc *SGXConstraints) ContainsEnclave(eid sgx.EnclaveIdentity) bool {
	return slices.Contains(sc.Enclaves, eid)
}

// EffectivePolicy returns a combined policy. The combined policy may in addition to the default policy,
// (depending on the specified roles) also include additional per-role policies.
func (sc *SGXConstraints) EffectivePolicy(roles RolesMask) *quote.Policy {
	effectivePolicy := sc.Policy // TODO: Make this a deep copy or better yet ensure Merge produces it.
	if effectivePolicy == nil {
		effectivePolicy = &quote.Policy{}
	}

	for role, policy := range sc.PerRolePolicy {
		if role&roles == 0 {
			continue
		}
		// We are ignoring deprecated IAS part, possibly we could error if if set twice.
		effectivePolicy.PCS = effectivePolicy.PCS.Merge(policy.PCS)
	}

	return effectivePolicy
}

const (
	// LatestSGXAttestationVersion is the latest SGX attestation structure version that should be
	// used for all new descriptors.
	LatestSGXAttestationVersion = 1
)

// SGXAttestation is an Intel SGX remote attestation.
type SGXAttestation struct {
	cbor.Versioned

	// Quote is an Intel SGX quote.
	Quote quote.Quote `json:"quote"`

	// Height is the runtime's view of the consensus layer height at the time of attestation.
	Height uint64 `json:"height"`

	// Signature is the signature of the attestation by the enclave (RAK).
	Signature signature.RawSignature `json:"signature"`
}

// UnmarshalCBOR is a custom deserializer that handles different structure versions.
func (sa *SGXAttestation) UnmarshalCBOR(data []byte) error {
	// Determine Entity structure version.
	v, err := cbor.GetVersion(data)
	if err != nil {
		v = 0 // Previous SGXAttestation structures were not versioned.
	}
	switch v {
	case 0:
		// Old version only supported the IAS attestation.
		var sav0 ias.AVRBundle
		if err = cbor.Unmarshal(data, &sav0); err != nil {
			return err
		}

		// Convert into new format.
		sa.Versioned = cbor.NewVersioned(0)
		sa.Quote = quote.Quote{
			IAS: &sav0,
		}
		return nil
	case 1:
		// New version, call the default unmarshaler.
		type sav1 SGXAttestation
		return cbor.Unmarshal(data, (*sav1)(sa))
	default:
		return fmt.Errorf("invalid SGX attestation version: %d", v)
	}
}

// MarshalCBOR is a custom serializer that handles different structure versions.
func (sa *SGXAttestation) MarshalCBOR() ([]byte, error) {
	switch sa.V {
	case 0:
		// Old version only supported the IAS attestation.
		return cbor.Marshal(sa.Quote.IAS), nil
	default:
		type sav1 SGXAttestation
		return cbor.Marshal((*sav1)(sa)), nil
	}
}

// ValidateBasic performs basic structure validity checks.
func (sa *SGXAttestation) ValidateBasic(cfg *TEEFeatures) error {
	if cfg == nil {
		cfg = &emptyFeatures
	}

	// Before the PCS feature only v0 of SGX attestation is supported.
	if !cfg.SGX.PCS && sa.V != 0 {
		return fmt.Errorf("unsupported SGX attestation version: %d", sa.V)
	}
	// Sanity check version (should never fail as deserialization already checks this).
	if sa.V > LatestSGXAttestationVersion {
		return fmt.Errorf("unsupported SGX attestation version: %d", sa.V)
	}

	return nil
}

// Verify verifies the SGX attestation.
// TODO: Extensive test suite for this function that acts as integration test (consider mocking).
func (sa *SGXAttestation) Verify(
	cfg *TEEFeatures,
	ts time.Time,
	height uint64,
	sc *SGXConstraints,
	rak signature.PublicKey,
	rek *x25519.PublicKey,
	n *Node,
) error {
	if cfg == nil {
		cfg = &emptyFeatures
	}

	// Use defaults from consensus parameters.
	cfg.SGX.ApplyDefaultConstraints(sc)

	// Verify the quote againt the effective policy.
	policy := sc.EffectivePolicy(n.Roles)
	verifiedQuote, err := sa.Quote.Verify(policy, ts)
	if err != nil {
		return err
	}

	// Ensure that the MRENCLAVE/MRSIGNER match what is specified
	// in the TEE-specific constraints field.
	if !sc.ContainsEnclave(verifiedQuote.Identity) {
		return ErrBadEnclaveIdentity
	}

	// Ensure that the report data includes the hash of the node's RAK.
	var reportDataRAKHash hash.Hash
	_ = reportDataRAKHash.UnmarshalBinary(verifiedQuote.ReportData[:hash.Size])
	rakHash := HashRAK(rak)
	if !rakHash.Equal(&reportDataRAKHash) {
		return ErrRAKHashMismatch
	}

	// The last 32 bytes of the quote ReportData are deliberately
	// ignored.

	if cfg.SGX.SignedAttestations {
		// In case the signed attestation feature is enabled, verify the signature.
		return sa.verifyAttestationSignature(sc, rak, rek, verifiedQuote.ReportData, n.ID, height)
	}

	return nil
}

func (sa *SGXAttestation) verifyAttestationSignature(
	sc *SGXConstraints,
	rak signature.PublicKey,
	rek *x25519.PublicKey,
	reportData []byte,
	nodeID signature.PublicKey,
	height uint64,
) error {
	h := HashAttestation(reportData, nodeID, sa.Height, rek)
	if !rak.Verify(AttestationSignatureContext, h, sa.Signature[:]) {
		return ErrInvalidAttestationSignature
	}

	// Check height is relatively recent and not from the future.
	if sa.Height > height {
		return ErrAttestationFromFuture
	}
	if age := height - sa.Height; age > sc.MaxAttestationAge {
		return fmt.Errorf("node: TEE attestation not fresh enough (age: %d max: %d)", age, sc.MaxAttestationAge)
	}

	return nil
}

// HashAttestation hashes the required data that needs to be signed by RAK producing the attestation
// signature. The hash is computed as follows:
//
//	TupleHash[AttestationSignatureContext](reportData, nodeID, height, *rek)
func HashAttestation(reportData []byte, nodeID signature.PublicKey, height uint64, rek *x25519.PublicKey) []byte {
	h := tuplehash.New256(32, []byte(AttestationSignatureContext))
	_, _ = h.Write(reportData)
	rawNodeID, _ := nodeID.MarshalBinary()
	_, _ = h.Write(rawNodeID)
	var rawHeight [8]byte
	binary.LittleEndian.PutUint64(rawHeight[:], height)
	_, _ = h.Write(rawHeight[:])
	if rek != nil {
		_, _ = h.Write(rek[:])
	}
	return h.Sum(nil)
}
