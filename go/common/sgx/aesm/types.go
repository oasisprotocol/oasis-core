package aesm

import (
	"encoding/binary"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/sgx"
)

// AttestationKeyType is the attestation key type.
type AttestationKeyType uint32

const (
	// AttestationKeyEPIDUnlinkable is the unlinkable EPID attestation key type.
	AttestationKeyEPIDUnlinkable AttestationKeyType = 0
	// AttestationKeyEPIDLinkable is the unlinkable EPID attestation key type.
	AttestationKeyEPIDLinkable AttestationKeyType = 1
	// AttestationKeyECDSA_P256 is the ECDSA-P256 attestation key type.
	AttestationKeyECDSA_P256 AttestationKeyType = 2 // nolint: revive
)

// String returns a string representation of the attestation key type.
func (kt AttestationKeyType) String() string {
	switch kt {
	case AttestationKeyEPIDUnlinkable:
		return "EPID-unlinkable"
	case AttestationKeyEPIDLinkable:
		return "EPID-linkable"
	case AttestationKeyECDSA_P256:
		return "ECDSA-P256"
	default:
		return "[unknown]"
	}
}

// AttestationKeyID is the parsed attestation key ID.
type AttestationKeyID struct {
	// Index is the key index.
	Index uint32

	// Type is the attestation key type.
	Type AttestationKeyType

	// MrSigner is the MRSIGNER of the Quoting Enclave.
	MrSigner sgx.MrSigner

	// raw contains the raw representation of the attestation key ID which is needed in AESM API.
	raw []byte
}

// String returns a string representation of the attestation key identifier.
func (ak AttestationKeyID) String() string {
	return fmt.Sprintf("<AttestationKeyID index=%d type=%s MRSIGNER=%s>", ak.Index, ak.Type, ak.MrSigner)
}

// UnmarshalBinary decodes a binary marshaled attestation key identifier.
func (ak *AttestationKeyID) UnmarshalBinary(data []byte) error {
	// See common/inc/sgx_quote.h in Intel SDK for details.
	const (
		// Offset of mrsigner_length in sgx_att_key_id_ext_t.
		sgxOffsetMrSignerLen = 4
		// Offset of mrsigner in sgx_att_key_id_ext_t.
		sgxOffsetMrSigner = 6
		// Offset of algorithm_id in sgx_att_key_id_ext_t.
		sgxOffsetAlgorithmID = 154
		// Size of the sgx_att_key_id_ext_t structure.
		sgxSizeKeyID = 158
	)

	if len(data) < sgxSizeKeyID {
		return fmt.Errorf("malformed attestation key ID (size: %d expected: %d)", len(data), sgxSizeKeyID)
	}

	mrSignerLen := int(binary.LittleEndian.Uint16(data[sgxOffsetMrSignerLen : sgxOffsetMrSignerLen+2]))
	if mrSignerLen != sgx.MrSignerSize {
		return fmt.Errorf("unsupported MRSIGNER size (got: %d expected: %d)", mrSignerLen, sgx.MrSignerSize)
	}

	var mrSigner sgx.MrSigner
	if err := mrSigner.UnmarshalBinary(data[sgxOffsetMrSigner : sgxOffsetMrSigner+mrSignerLen]); err != nil {
		return fmt.Errorf("bad MRSIGNER: %w", err)
	}

	algID := binary.LittleEndian.Uint32(data[sgxOffsetAlgorithmID : sgxOffsetAlgorithmID+4])
	switch AttestationKeyType(algID) {
	case AttestationKeyEPIDUnlinkable, AttestationKeyEPIDLinkable, AttestationKeyECDSA_P256:
	default:
		return fmt.Errorf("unsupported key algorithm: %d", algID)
	}

	ak.Index = 0
	ak.Type = AttestationKeyType(algID)
	ak.MrSigner = mrSigner
	ak.raw = data

	return nil
}
