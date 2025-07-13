package api

const (
	// MethodGetConfig is the name of the `get_config` method.
	MethodGetConfig = "rofl.GetConfig"
)

// Config is runtime application configuration.
type Config struct {
	/// Notification are notifications settings.
	Notifications Notifications `json:"notifications"`
}

// Notifications are notification settings.
type Notifications struct {
	/// Blocks subscribe to runtime block notifications.
	Blocks bool `json:"blocks,omitempty"`
	/// Events subscribe to runtime event notifications associated
	/// with the specified tags.
	Events [][]byte `json:"events,omitempty"`
}
