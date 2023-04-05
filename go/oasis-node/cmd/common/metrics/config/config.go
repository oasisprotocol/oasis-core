// Package config implements global metrics configuration options.
package config

import (
	"fmt"
	"time"
)

// Config is the metrics configuration structure.
type Config struct {
	// Metrics mode (none, pull, push).
	Mode string `yaml:"mode"`
	// Metrics pull address.
	Address string `yaml:"address"`

	// Metrics push job name (debug-only).
	JobName string `yaml:"job_name,omitempty"`
	// Metrics push instance labels (debug-only).
	Labels map[string]string `yaml:"labels,omitempty"`
	// Metrics push interval (debug-only).
	Interval time.Duration `yaml:"interval,omitempty"`
}

// Validate validates the configuration settings.
func (c *Config) Validate() error {
	switch c.Mode {
	case "none":
	case "pull":
		if len(c.Address) == 0 {
			return fmt.Errorf("missing address in pull mode")
		}
	case "push":
		if len(c.Address) == 0 {
			return fmt.Errorf("missing address in push mode")
		}
		if len(c.JobName) == 0 {
			return fmt.Errorf("missing job_name in push mode")
		}
		if len(c.Labels) == 0 {
			return fmt.Errorf("missing labels in push mode")
		}
		if c.Interval == 0 {
			return fmt.Errorf("missing interval in push mode")
		}
	default:
		return fmt.Errorf("unknown metrics mode: %s", c.Mode)
	}

	return nil
}

// DefaultConfig returns the default configuration settings.
func DefaultConfig() Config {
	return Config{
		Mode:     "none",
		Address:  "127.0.0.1:3000",
		JobName:  "",
		Labels:   map[string]string{},
		Interval: 5 * time.Second,
	}
}
