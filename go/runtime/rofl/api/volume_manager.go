package api

const (
	// LocalRPCEndpointVolumeManager is the name of the local RPC endpoint for the volume manager.
	LocalRPCEndpointVolumeManager = "volume-manager"

	// MethodVolumeAdd is the name of the VolumeAdd method.
	MethodVolumeAdd = "VolumeAdd"
	// MethodVolumeRemove is the name of the VolumeRemove method.
	MethodVolumeRemove = "VolumeRemove"
	// MethodVolumeList is the name of the VolumeList method.
	MethodVolumeList = "VolumeList"
)

// VolumeAddRequest is a request to add a volume.
//
// The `PermissionVolumeAdd` permission is required to call this method.
type VolumeAddRequest struct {
	// Labels are the labels to tag the volume with so it can later be found.
	Labels map[string]string `json:"labels"`
}

// VolumeAddResponse is a response from the VolumeAdd method.
type VolumeAddResponse struct {
	// ID is the unique volume identifier.
	ID string `json:"id"`
}

// VolumeRemoveRequest is a request to remove volumes.
//
// The `PermissionVolumeRemove` permission is required to call this method.
type VolumeRemoveRequest struct {
	// Labels are the labels to filter the volumes by. All labels must match.
	Labels map[string]string `json:"labels"`
}

// VolumeRemoveResponse is a response from the VolumeRemove method.
type VolumeRemoveResponse struct{}

// VolumeListRequest is a request to list volumes.
//
// The `PermissionVolumeAdd` permission is required to call this method.
type VolumeListRequest struct {
	// Labels are the labels to filter the volumes by. All labels must match.
	Labels map[string]string `json:"labels"`
}

// VolumeListResponse is a response from the VolumeList method.
type VolumeListResponse struct {
	Volumes []*VolumeInfo `json:"volumes,omitempty"`
}

// VolumeInfo is the volume information.
type VolumeInfo struct {
	// ID is the unique volume identifier.
	ID string `json:"id"`
	// Labels is a set of labels assigned to this volume.
	Labels map[string]string `json:"labels,omitempty"`
}
