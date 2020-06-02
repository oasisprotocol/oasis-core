// Package accessctl implements access control for an Oasis node.
package accessctl

import (
	"crypto/ed25519"
	"crypto/x509"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

// Subject is an access control subject.
type Subject string

// SubjectFromX509Certificate returns a Subject from the given X.509
// certificate.
func SubjectFromX509Certificate(cert *x509.Certificate) Subject {
	pk, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		// This should never happen if certificates are properly verified.
		return ""
	}
	var spk signature.PublicKey
	if err := spk.UnmarshalBinary(pk[:]); err != nil {
		// This should NEVER happen.
		return ""
	}

	return SubjectFromPublicKey(spk)
}

// SubjectFromPublicKey returns a Subject from the given public key.
func SubjectFromPublicKey(pubKey signature.PublicKey) Subject {
	return Subject(pubKey.String())
}

// Action is an access control action.
type Action string

// Policy maps from Actions to a mapping from Subjects to booleans indicating
// whether the given subject is allowed to perform the given action or not.
//
// The policy is not safe for concurrent use.
type Policy map[Action]map[Subject]bool

// NewPolicy returns an empty policy.
func NewPolicy() Policy {
	return make(Policy)
}

// Allow adds a policy rule that allows the given Subject to perform the given
// Action.
func (p Policy) Allow(sub Subject, act Action) {
	if p[act] == nil {
		p[act] = make(map[Subject]bool)
	}
	p[act][sub] = true
}

// Deny removes a policy rule that allows the given Subject to perform the
// given Action.
func (p Policy) Deny(sub Subject, act Action) {
	if p[act] == nil {
		return
	}
	delete(p[act], sub)
}

// IsAllowed returns a boolean indicating whether the given Subject is allowed
// to perform the given Action under the current Policy.
func (p Policy) IsAllowed(sub Subject, act Action) bool {
	if p[act] == nil {
		return false
	}
	return p[act][sub]
}

// String returns the string representation of the policy.
func (p Policy) String() string {
	return fmt.Sprintf("%#v", p)
}
