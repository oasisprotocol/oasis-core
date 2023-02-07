// Package config implements global configuration options.
package config

// Config is the common configuration structure.
type Config struct {
	// Node's data directory.
	DataDir string `yaml:"data_dir"`
	// Logging configuration options.
	Log LogConfig `yaml:"log,omitempty"`
	// Debug configuration options (do not use).
	Debug DebugConfig `yaml:"debug,omitempty"`
}

// LogConfig is the common logging configuration structure.
type LogConfig struct {
	// Log file.
	File string `yaml:"file,omitempty"`
	// Log format (logfmt, json).
	Format string `yaml:"format,omitempty"`
	// Log level (debug, info, warn, error) per module.
	Level map[string]string `yaml:"level,omitempty"`
}

// DebugConfig is the common debug configuration structure.
type DebugConfig struct {
	// Allow running the node as root.
	AllowRoot bool `yaml:"allow_root,omitempty"`
	// Set RLIMIT_NOFILE to this value on launch (0 means don't set).
	Rlimit uint64 `yaml:"rlimit,omitempty"`
}

// Validate validates the configuration settings.
func (c *Config) Validate() error {
	return nil
}

// DefaultConfig returns the default configuration settings.
func DefaultConfig() Config {
	return Config{
		DataDir: "",
		Log: LogConfig{
			File:   "",
			Format: "logfmt",
			Level:  make(map[string]string),
		},
		Debug: DebugConfig{
			AllowRoot: false,
			Rlimit:    0,
		},
	}
}
