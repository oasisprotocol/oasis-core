package events

import (
	"encoding/base64"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
)

// Provable is an interface implemented by event types which can be proven.
type Provable interface {
	// ShouldProve returns true iff the event should be included in the event proof tree.
	ShouldProve() bool

	// ProvableRepresentation returns the provable representation of an event.
	//
	// Since this representation is part of commitments that are included in consensus layer state
	// any changes to this representation are consensus-breaking.
	ProvableRepresentation() any
}

// TypedAttribute is an interface implemented by types which can be transparently used as event
// attributes with CBOR-marshalled value.
type TypedAttribute interface {
	// EventKind returns a string representation of this event's kind.
	EventKind() string
}

// CustomTypedAttribute is an interface implemented by types which can be transparently used as event
// attributes with custom value encoding.
type CustomTypedAttribute interface {
	TypedAttribute

	// EventValue returns a string representation of this events value.
	EventValue() string

	// DecodeValue decodes the value encoded vy the EventValue.
	DecodeValue(value string) error
}

// IsAttributeKind checks whether the given attribute key corresponds to the passed typed attribute.
func IsAttributeKind(key string, kind TypedAttribute) bool {
	return key == kind.EventKind()
}

// DecodeValue decodes the attribute event value.
func DecodeValue(value string, ev TypedAttribute) error {
	// Use custom decode if this is a custom typed attribute.
	if cta, ok := ev.(CustomTypedAttribute); ok {
		return cta.DecodeValue(value)
	}
	// Otherwise assume default base64 encoded CBOR marshalled value.
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return fmt.Errorf("invalid value: %w", err)
	}
	return cbor.Unmarshal(decoded, ev)
}

// EncodeValue encodes the attribute event value.
func EncodeValue(ev TypedAttribute) string {
	// Use custom decode if this is a custom typed attribute.
	if cta, ok := ev.(CustomTypedAttribute); ok {
		return cta.EventValue()
	}
	// Otherwise default to base64 encoded CBOR marshalled value.
	return base64.StdEncoding.EncodeToString(cbor.Marshal(ev))
}
