// Package config implements global configuration options.
package config

// Config is the keymanager worker configuration structure.
type Config struct {
	// Key manager Runtime ID.
	RuntimeID string `yaml:"runtime_id"`
	// Key manager may generate a new master secret.
	MayGenerate bool `yaml:"may_generate"`
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
		MayGenerate:        false,
		PrivatePeerPubKeys: []string{},
	}
}
