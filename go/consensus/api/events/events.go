package events

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
)

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
func IsAttributeKind(key []byte, kind TypedAttribute) bool {
	return bytes.Equal(key, []byte(kind.EventKind()))
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
func EncodeValue(ev TypedAttribute) []byte {
	// Use custom decode if this is a custom typed attribute.
	if cta, ok := ev.(CustomTypedAttribute); ok {
		return []byte(cta.EventValue())
	}
	// Otherwise default to base64 encoded CBOR marshalled value.
	return []byte(base64.StdEncoding.EncodeToString(cbor.Marshal(ev)))
}
