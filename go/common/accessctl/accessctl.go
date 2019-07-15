// Package accessctl implements access control for Ekiden.
package accessctl

import (
	"crypto/x509"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
)

// Subject is an access control subject.
type Subject string

// SubjectFromX509Certificate returns a Subject from the given X.509
// certificate.
func SubjectFromX509Certificate(cert *x509.Certificate) Subject {
	return SubjectFromDER(cert.Raw)
}

// SubjectFromDER returns a Subject from the given certificate's ASN.1 DER
// representation. To do so, it computes the hash of the DER representation.
func SubjectFromDER(der []byte) Subject {
	var h = hash.Hash{}
	h.FromBytes(der)
	return Subject(h.String())
}

// Action is an access control action.
type Action string

// Policy maps from Actions to a mapping from Subjects to booleans indicating
// whether the given subject is allowed to perform the given action or not.
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
