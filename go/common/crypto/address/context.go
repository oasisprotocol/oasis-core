package address

import (
	"encoding"
	"errors"
	"fmt"
	"sync"
)

// ContextMaxSize is the maximum size of a context's identifier string.
const ContextIdentifierMaxSize = 64

var (
	// ErrMalformedContext is the error returned when an address context is malformed.
	ErrMalformedContext = errors.New("address: malformed context")

	registeredContexts sync.Map

	_ encoding.BinaryMarshaler = Context{}
)

// Context is a domain separation context for addresses.
type Context struct {
	// Identifier is the context's identifier string.
	Identifier string
	// Version is the context's version.
	Version uint8
}

// MarshalBinary encodes a context into binary form.
func (c Context) MarshalBinary() (data []byte, err error) {
	data = append([]byte(c.Identifier), c.Version)
	return
}

// String returns a string representation of address' context.
func (c Context) String() string {
	return fmt.Sprintf("Context(Identifier: '%s', Version: %d)", c.Identifier, c.Version)
}

// NewContext creates and registers a new context.  This routine will panic if
// the context is malformed or is already registered.
func NewContext(identifier string, version uint8) Context {
	// NOTE: We disallow identifier lengths of 0 to enforce strict domain separation.
	l := len(identifier)
	if l == 0 {
		panic(ErrMalformedContext)
	}
	if l > ContextIdentifierMaxSize {
		panic(ErrMalformedContext)
	}

	ctx := Context{identifier, version}
	if _, loaded := registeredContexts.LoadOrStore(ctx, true); loaded {
		panic(fmt.Sprintf("address: context %s is already registered", ctx))
	}

	return ctx
}
