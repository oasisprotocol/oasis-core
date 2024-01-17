// Package config implements global configuration options.
package config

// Config is the keymanager worker configuration structure.
type Config struct {
	// Key manager Runtime ID.
	RuntimeID string `yaml:"runtime_id"`
	// Base64-encoded public keys of unadvertised peers that may call protected methods.
	PrivatePeerPubKeys []string `yaml:"private_peer_pub_keys"`
}

// Validate validates the configuration settings.
func (c *Config) Validate() error {
	return nil
}

// DefaultConfig returns the default configuration settings.
func DefaultConfig() Config {
	return Config{
		RuntimeID:          "",
		PrivatePeerPubKeys: []string{},
	}
}
