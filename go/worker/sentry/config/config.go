// Package config implements global configuration options.
package config

// Config is the sentry worker configuration structure.
type Config struct {
	// Enable Sentry worker.
	// NOTE: This should only be enabled on Sentry nodes.
	Enabled bool `yaml:"enabled"`

	Control ControlConfig `yaml:"control,omitempty"`
}

// ControlConfig is the sentry worker control configuration structure.
type ControlConfig struct {
	// Sentry worker's gRPC server port.
	Port uint16 `yaml:"port"`

	// Public keys of upstream nodes that are allowed to connect to sentry control endpoint.
	AuthorizedPubkeys []string `yaml:"authorized_pubkeys"`
}

// Validate validates the configuration settings.
func (c *Config) Validate() error {
	return nil
}

// DefaultConfig returns the default configuration settings.
func DefaultConfig() Config {
	return Config{
		Enabled: false,
		Control: ControlConfig{
			Port:              9009,
			AuthorizedPubkeys: []string{},
		},
	}
}
