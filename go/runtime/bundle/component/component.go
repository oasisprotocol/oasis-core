// Package component contains types for runtime components.
package component

import (
	"fmt"
	"strings"
)

// Kind is the kind of a component.
type Kind string

const (
	// RONL is the on-chain logic component.
	RONL Kind = "ronl"
	// ROFL is the off-chain logic component.
	ROFL Kind = "rofl"
)

const kindNameSeparator = "."

// ID is a unique component identifier.
type ID struct {
	// Kind is the component kind.
	Kind Kind `json:"kind"`

	// Name is an optional component name.
	Name string `json:"name,omitempty"`
}

// String returns a string representation of the component identifier.
func (c ID) String() string {
	if c.Name == "" {
		return string(c.Kind)
	}
	return string(c.Kind) + " (" + c.Name + ")"
}

// MarshalText serializes the component identifier into text form.
func (c ID) MarshalText() ([]byte, error) {
	if c.Name == "" {
		return []byte(string(c.Kind)), nil
	}
	return []byte(string(c.Kind) + kindNameSeparator + c.Name), nil
}

// UnmarshalText deserializes the component identifier from text form.
func (c *ID) UnmarshalText(text []byte) error {
	atoms := strings.SplitN(string(text), kindNameSeparator, 2)

	if len(atoms) == 2 && atoms[1] == "" {
		return fmt.Errorf("malformed component identifier")
	}

	var kind Kind
	switch atoms[0] {
	case string(RONL):
		kind = RONL
	case string(ROFL):
		kind = ROFL
	default:
		return fmt.Errorf("malformed component kind: %s", atoms[0])
	}

	if kind == RONL && len(atoms) > 1 && len(atoms[1]) > 0 {
		return fmt.Errorf("RONL component must have an empty name, got: %s", atoms[1])
	}

	c.Kind = kind
	if len(atoms) > 1 {
		c.Name = atoms[1]
	} else {
		c.Name = ""
	}
	return nil
}

// IsRONL returns true iff the component identifier is the special RONL component identifier.
func (c ID) IsRONL() bool {
	return c == ID_RONL
}

// ID_RONL is the identifier of the RONL component.
var ID_RONL = ID{Kind: RONL, Name: ""} //nolint: revive
