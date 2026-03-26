// Package config implements global configuration options.
package config

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
)

// Config is the registration worker configuration structure.
type Config struct {
	// Entity to use as the node owner in registrations (path to the JSON file).
	Entity string `yaml:"entity"`

	// EntityID to use as the node owner in registrations (public key).
	EntityID string `yaml:"entity_id"`
}

// Validate validates the configuration settings.
func (c *Config) Validate() error {
	// Ensure only one of Entity/EntityID is set.
	if !common.AtMostOneTrue(
		c.Entity != "",
		c.EntityID != "",
	) {
		return fmt.Errorf("only one of `entity` and `entity_id` must be set")
	}

	// Ensure the entity ID is valid if passed.
	if c.EntityID != "" {
		var id signature.PublicKey
		if err := id.UnmarshalText([]byte(c.EntityID)); err != nil {
			return fmt.Errorf("malformed entity ID: %w", err)
		}
	}
	return nil
}

// ResolveEntityID resolves the owning entity ID.
//
// In case of no configured entity a nil value is returned.
func (c *Config) ResolveEntityID() (*signature.PublicKey, error) {
	switch {
	case c.Entity != "":
		ent, err := entity.LoadDescriptor(c.Entity)
		if err != nil {
			return nil, fmt.Errorf("failed to load entity descriptor: %w", err)
		}

		return &ent.ID, nil
	case c.EntityID != "":
		var entityID signature.PublicKey
		if err := entityID.UnmarshalText([]byte(c.EntityID)); err != nil {
			return nil, fmt.Errorf("malformed entity ID: %w", err)
		}

		return &entityID, nil
	default:
		return nil, nil
	}
}

// DefaultConfig returns the default configuration settings.
func DefaultConfig() Config {
	return Config{
		Entity:   "",
		EntityID: "",
	}
}
