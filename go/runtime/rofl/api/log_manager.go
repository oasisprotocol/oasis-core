package api

const (
	// LocalRPCEndpointLogManager is the name of the local RPC endpoint for the log manager.
	LocalRPCEndpointLogManager = "log-manager"

	// MethodLogGet is the name of the LogGet method.
	MethodLogGet = "LogGet"
)

// LogGetRequest is a request to host to fetch logs.
//
// The `PermissionLogView` permission is required to call this method.
type LogGetRequest struct {
	// Labels are the labels to filter the bundles by. All labels must match and only the
	// first bundle is used.
	Labels map[string]string `json:"labels"`
	// ComponentID is the identifier of the component in the bundle.
	ComponentID string `json:"component_id"`
	// Since is an optional UNIX timestamp to filter log entries by. Only entries with higher
	// timestamps will be returned.
	Since uint64 `json:"since,omitempty"`
}

// LogGetResponse is a response from the LogGet method.
type LogGetResponse struct {
	// Logs are the log lines for the given component.
	Logs []string `json:"logs"`
}
