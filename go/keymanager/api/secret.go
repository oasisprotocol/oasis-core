package api

import (
	"fmt"

	"github.com/oasisprotocol/curve25519-voi/primitives/x25519"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

// minEnclavesPercent is the minimum percentage of key manager enclaves from the key manager
// committee to which the ephemeral secret needs to be encrypted.
const minEnclavesPercent = 66

// EncryptedEphemeralSecretSignatureContext is the context used to sign encrypted key manager ephemeral secrets.
var EncryptedEphemeralSecretSignatureContext = signature.NewContext("oasis-core/keymanager: encrypted ephemeral secret")

// EncryptedEphemeralSecret is a REK encrypted ephemeral secret.
type EncryptedEphemeralSecret struct {
	// ID is the runtime ID of the key manager.
	ID common.Namespace `json:"runtime_id"`

	// Epoch is the epoch to which the ephemeral secret belongs.
	Epoch beacon.EpochTime `json:"epoch"`

	// Checksum is the ephemeral secret verification checksum.
	Checksum []byte `json:"checksum"`

	// PublicKey is the public part of the key which was used to encrypt the ephemeral secret.
	PublicKey x25519.PublicKey `json:"public_key"`

	// Ciphertexts is the map of REK encrypted ephemeral secrets for all known key manager enclaves.
	Ciphertexts map[x25519.PublicKey][]byte `json:"ciphertexts"`
}

// SanityCheck performs a sanity check on the ephemeral secret.
func (s *EncryptedEphemeralSecret) SanityCheck(epoch beacon.EpochTime, reks map[x25519.PublicKey]struct{}) error {
	if epoch != s.Epoch {
		return fmt.Errorf("keymanager: sanity check failed: ephemeral secret contains an invalid epoch: (expected: %d, got: %d)", epoch, s.Epoch)
	}

	// Secret should be encrypted to at least one member of the key manager committee.
	if len(reks) == 0 {
		return fmt.Errorf("keymanager: sanity check failed: ephemeral secret cannot be encrypted to an empty committee")
	}

	// Secret should be encrypted to the enclaves from the key manager committee only.
	for rek := range s.Ciphertexts {
		if _, ok := reks[rek]; !ok {
			return fmt.Errorf("keymanager: sanity check failed: ephemeral secret contains unknown REK")
		}
	}

	// Most of the enclaves should be able to decrypt the secret.
	percent := len(s.Ciphertexts) * 100 / len(reks)
	if percent < minEnclavesPercent {
		return fmt.Errorf("keymanager: sanity check failed: ephemeral secret is not encrypted to enough enclaves")
	}

	return nil
}

// SignedEncryptedEphemeralSecret is a RAK signed encrypted ephemeral secret.
type SignedEncryptedEphemeralSecret struct {
	// Secret is the encrypted ephemeral secret to which the signature belongs.
	Secret EncryptedEphemeralSecret `json:"secret"`

	// Signature is a signature of the ephemeral secret.
	Signature signature.RawSignature `json:"signature"`
}

// Verify sanity checks the encrypted ephemeral secret and verifies its signature.
func (s *SignedEncryptedEphemeralSecret) Verify(epoch beacon.EpochTime, reks map[x25519.PublicKey]struct{}, rak signature.PublicKey) error {
	// Verify the secret.
	if err := s.Secret.SanityCheck(epoch, reks); err != nil {
		return err
	}

	// Verify the signature.
	raw := cbor.Marshal(s.Secret)
	if !rak.Verify(EncryptedEphemeralSecretSignatureContext, raw, s.Signature[:]) {
		return fmt.Errorf("keymanager: sanity check failed: ephemeral secret contains an invalid signature")
	}

	return nil
}
