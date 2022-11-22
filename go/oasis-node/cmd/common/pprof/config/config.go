// Package config implements global configuration options.
package config

// Config is the pprof configuration structure.
type Config struct {
	// Enable profiling endpoint at given address.
	BindAddress string `yaml:"bind_address"`
}

// Validate validates the configuration settings.
func (c *Config) Validate() error {
	return nil
}

// DefaultConfig returns the default configuration settings.
func DefaultConfig() Config {
	return Config{
		BindAddress: "",
	}
}
