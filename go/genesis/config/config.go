// Package config contains the genesis document-related configuration.
package config

import "fmt"

// Config is the genesis document configuration.
type Config struct {
	// File is the path to the genesis document file.
	File string `yaml:"file"`
}

// Validate validates the configuration settings.
func (c *Config) Validate() error {
	if len(c.File) == 0 {
		return fmt.Errorf("missing genesis file path")
	}

	return nil
}

// DefaultConfig returns the default configuration settings.
func DefaultConfig() Config {
	return Config{
		File: "genesis.json",
	}
}
