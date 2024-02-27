// Package config implements global configuration options.
package config

// ChurpConfig holds configuration details for the CHURP extension.
type ChurpConfig struct {
	// Schemes is a list of CHURP scheme configurations.
	Schemes []ChurpSchemeConfig `yaml:"schemes,omitempty"`
}

// ChurpSchemeConfig holds configuration details for a CHURP scheme.
type ChurpSchemeConfig struct {
	// ID is the unique identifier of the CHURP scheme.
	ID uint8 `yaml:"id,omitempty"`
}

// Config is the keymanager worker configuration structure.
type Config struct {
	// Key manager runtime ID.
	RuntimeID string `yaml:"runtime_id"`
	// Base64-encoded public keys of unadvertised peers that may call protected methods.
	PrivatePeerPubKeys []string `yaml:"private_peer_pub_keys"`

	// Churp holds configuration details for the CHURP extension.
	Churp ChurpConfig `yaml:"churp,omitempty"`
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
		Churp: ChurpConfig{
			Schemes: []ChurpSchemeConfig{},
		},
	}
}
