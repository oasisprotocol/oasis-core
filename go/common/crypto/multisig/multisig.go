// Package multisig implements the multisig envelope format and
// associated types.
package multisig

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/bits"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
)

var (
	_ prettyprint.PrettyPrinter = (*AccountSigner)(nil)
	_ prettyprint.PrettyPrinter = (*Account)(nil)
	_ prettyprint.PrettyPrinter = (*PrettyEnvelope)(nil)
)

// AccountSigner is a signer associated with an account.
type AccountSigner struct {
	// PublicKey is the account signer's public key.
	PublicKey signature.PublicKey `json:"public_key"`

	// Weight is the account signer's signing weight.
	Weight uint64 `json:"weight"`
}

// PrettyPrint writes a pretty-printed representation of the type to
// the given writer.
func (signer AccountSigner) PrettyPrint(context context.Context, prefix string, w io.Writer) {
	data, err := json.MarshalIndent(signer, prefix, "  ")
	if err != nil {
		fmt.Fprintf(w, "%s<error: %s>\n", prefix, err)
		return
	}
	fmt.Fprintf(w, "%s%s\n", prefix, data)
}

// PrettyType returns a representation of the type that can be used for
// pretty printing.
func (signer AccountSigner) PrettyType() (interface{}, error) {
	return signer, nil
}

// Account is an account descriptor.
type Account struct {
	cbor.Versioned

	// Signers are the account signers associated with the given
	// account.
	Signers []AccountSigner `json:"signers,omitempty"`

	// Threshold is the minimum combined weight that must be
	// met (>=) for a payload to be considered valid.
	Threshold uint64 `json:"threshold"`
}

// Verify validates an account descriptor for well-formedness.
func (acc *Account) Verify() error {
	if acc.V != 0 {
		return fmt.Errorf("crypto/multisig: invalid version: %v", acc.V)
	}
	if len(acc.Signers) == 0 {
		return fmt.Errorf("crypto/multisig: no account signers")
	}

	pkMap := make(map[signature.PublicKey]bool)
	var sum, carry uint64
	for _, v := range acc.Signers {
		pk := v.PublicKey
		if !pk.IsValid() {
			return fmt.Errorf("crypto/multisig: invalid account signer: '%s'", pk)
		}
		if pkMap[pk] {
			return fmt.Errorf("crypto/multisig: duplicate account signer: '%s'", pk)
		}
		pkMap[pk] = true

		if v.Weight == 0 {
			return fmt.Errorf("crypto/multisig: invalid account signing weight: '%s'", pk)
		}

		sum, carry = bits.Add64(sum, v.Weight, 0)
		if carry != 0 {
			return fmt.Errorf("crypto/multisig: total signing weight overflow")
		}
	}

	if acc.Threshold == 0 {
		return fmt.Errorf("crypto/multisig: invalid account threshold")
	}
	if sum < acc.Threshold {
		return fmt.Errorf("crypto/multisig: threshold %d exceeds available signing power %d", acc.Threshold, sum)
	}

	// Strictly speaking this isn't required, but forcing all single
	// signer accounts to be of the form created by NewAccountFromPublicKey
	// seems like a reasonable thing to do.
	if len(acc.Signers) == 1 && sum != 1 {
		return fmt.Errorf("crypto/multisig: invalid signing power %d for single signer account", sum)
	}

	return nil
}

// Hash returns the hash of the account descriptor.
func (acc *Account) Hash() []byte {
	h := hash.NewFrom(acc)
	return h[:]
}

// PrettyPrint writes a pretty-printed representation of the type to
// the given writer.
func (acc Account) PrettyPrint(context context.Context, prefix string, w io.Writer) {
	data, err := json.MarshalIndent(acc, prefix, "  ")
	if err != nil {
		fmt.Fprintf(w, "%s<error: %s>\n", prefix, err)
		return
	}
	fmt.Fprintf(w, "%s%s\n", prefix, data)
}

// PrettyType returns a representation of the type that can be used for
// pretty printing.
func (acc Account) PrettyType() (interface{}, error) {
	return acc, nil
}

// NewAccountFromPublicKey creates an account descriptor containing a
// single public key.
func NewAccountFromPublicKey(pk signature.PublicKey) *Account {
	return &Account{
		Signers: []AccountSigner{
			{
				PublicKey: pk,
				Weight:    1,
			},
		},
		Threshold: 1,
	}
}

// Envelope is a multisig envelope.
type Envelope struct {
	// Account is the account signing this payload.
	Account Account `json:"account"`

	// Signatures are the signatures covering `Account.Address () || Payload`
	// for this envelope, sorted in the order that the public keys
	// appear in the account descriptor.
	//
	// If a signature is missing for a given signer, the corresponding
	// entry in the vector will be `nil`.
	Signatures []*signature.RawSignature `json:"signatures,omitempty"`

	// Payload is the raw payload.
	Payload []byte `json:"payload,omitempty"`
}

// Verify verifies an envelope and its signature(s).
func (e *Envelope) Verify(context signature.Context) error {
	if err := e.Account.Verify(); err != nil {
		return err
	}

	if len(e.Signatures) != len(e.Account.Signers) {
		return fmt.Errorf("crypto/multisig: invalid number of signatures")
	}

	var (
		sigs []signature.Signature
		sum  uint64
	)
	for i, v := range e.Signatures {
		if v == nil {
			continue
		}
		if len(v) != signature.SignatureSize {
			return fmt.Errorf("crypto/multisig: malformed signature(s)")
		}

		signer := e.Account.Signers[i]
		sigs = append(sigs, signature.Signature{
			PublicKey: signer.PublicKey,
			Signature: *v,
		})
		sum += signer.Weight // Overflow checked in Account.Verify.
	}

	msg := append(e.Account.Hash(), e.Payload...)
	if !signature.VerifyManyToOne(context, msg, sigs) {
		// Note: Envelopes with any invalid signatures will be rejected
		// by this.  In theory, there could be enough valid signatures
		// with sufficient signing power, but in practice "don't do that
		// then".
		return fmt.Errorf("crypto/multisig: invalid signature(s)")
	}

	if sum < e.Account.Threshold {
		return fmt.Errorf("crypto/multisig: insufficent signing power")
	}

	return nil
}

// Open opens an envelope, and returns the payload after verifying the
// Account and signatures.
func (e *Envelope) Open(context signature.Context, dst interface{}) error {
	if err := e.Verify(context); err != nil {
		return err
	}

	if err := cbor.Unmarshal(e.Payload, dst); err != nil {
		return fmt.Errorf("crypto/multisig: malformed payload: %w", err)
	}

	return nil
}

// Sign signs a raw serialized payload for inclusion in an envelope.
func Sign(signer signature.Signer, account *Account, context signature.Context, payload []byte) (*signature.Signature, error) {
	// This could check if the signer is part of the account, but
	// leaving that to the caller is fine ("Don't do that then").
	msg := append(account.Hash(), payload...)
	return signature.Sign(signer, context, msg)
}

// NewEnvelope creates a new envelope from its components.
func NewEnvelope(account *Account, signatures []*signature.Signature, payload []byte) (*Envelope, error) {
	env := &Envelope{
		Account: *account,
		Payload: payload,
	}

	sigMap := make(map[signature.PublicKey]*signature.RawSignature)
	for _, v := range signatures {
		if sigMap[v.PublicKey] != nil {
			return nil, fmt.Errorf("crypto/multisig: redundant signature for '%s'", v.PublicKey)
		}
		sigMap[v.PublicKey] = &v.Signature
	}

	for _, v := range account.Signers {
		sig := sigMap[v.PublicKey]
		env.Signatures = append(env.Signatures, sig)
		delete(sigMap, v.PublicKey)
	}

	if len(sigMap) != 0 {
		return nil, fmt.Errorf("crypto/multisig: signatures not part of the account")
	}

	// Note: This could validate the account and final envelope but,
	// "don't do that then".

	return env, nil
}

// PrettyEnvelope is used for pretty-printing envelopes so that the actual
// content is displayed instead of the binary blob.
//
// It should only be used for pretty-printing.
type PrettyEnvelope struct {
	Account    Account                   `json:"account"`
	Signatures []*signature.RawSignature `json:"signatures,omitempty"`
	Payload    interface{}               `json:"payload,omitempty"`
}

// PrettyPrint writes a pretty-printed representation of the type to
// the given writer.
func (pe PrettyEnvelope) PrettyPrint(context context.Context, prefix string, w io.Writer) {
	data, err := json.MarshalIndent(pe, prefix, "  ")
	if err != nil {
		fmt.Fprintf(w, "%s<error: %s>\n", prefix, err)
		return
	}
	fmt.Fprintf(w, "%s%s\n", prefix, data)
}

// PrettyType returns a representation of the type that can be used for
// pretty printing.
func (pe PrettyEnvelope) PrettyType() (interface{}, error) {
	return pe, nil
}

// NewPrettyEnvelope creates a new PrettyEnvelope instance that can be
// used for pretty-printing envelopes.
func NewPrettyEnvelope(e Envelope, b interface{}) (*PrettyEnvelope, error) {
	if pp, ok := b.(prettyprint.PrettyPrinter); ok {
		var err error
		if b, err = pp.PrettyType(); err != nil {
			return nil, fmt.Errorf("failed to pretty print body: %w", err)
		}
	}

	return &PrettyEnvelope{
		Account:    e.Account,
		Signatures: e.Signatures,
		Payload:    b,
	}, nil
}
