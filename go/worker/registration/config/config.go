// Package config implements global configuration options.
package config

// Config is the registration worker configuration structure.
type Config struct {
	// Entity to use as the node owner in registrations (path to the JSON file).
	Entity string `yaml:"entity"`

	// Rotate node TLS certificates every N epochs (0 to disable).
	RotateCerts uint64 `yaml:"rotate_certs"`
}

// Validate validates the configuration settings.
func (c *Config) Validate() error {
	return nil
}

// DefaultConfig returns the default configuration settings.
func DefaultConfig() Config {
	return Config{
		Entity:      "",
		RotateCerts: 0,
	}
}
