package api

import "github.com/oasisprotocol/oasis-core/go/common/crypto/hash"

const (
	// LocalRPCEndpointBundleManager is the name of the local RPC endpoint for the bundle manager.
	LocalRPCEndpointBundleManager = "bundle-manager"

	// MethodBundleWrite is the name of the BundleWrite method.
	MethodBundleWrite = "BundleWrite"
	// MethodBundleAdd is the name of the BundleAdd method.
	MethodBundleAdd = "BundleAdd"
	// MethodBundleRemove is the name of the BundleRemove method.
	MethodBundleRemove = "BundleRemove"
	// MethodBundleList is the name of the BundleList method.
	MethodBundleList = "BundleList"
)

// BundleWriteRequest is a request to host to store a chunk of the bundle.
//
// The `PermissionBundleAdd` permission is required to call this method.
type BundleWriteRequest struct {
	// TemporaryName is a temporary name to identify the chunk later.
	TemporaryName string `json:"temporary_name"`
	// Create is the optional flag which specifies that the bundle should be recreated. If the
	// bundle exists and this flag is set to true, it will be truncated. If the flag is set to
	// false, any content will be appended to the existing bundle.
	Create bool `json:"create,omitempty"`
	// Data that should be appended to the bundle.
	Data []byte `json:"data"`
}

// BundleWriteResponse is the response from the BundleWrite method.
type BundleWriteResponse struct{}

// BundleAddRequest is a request to host to add a specific bundle to the host.
//
// The `PermissionBundleAdd` permission is required to call this method.
type BundleAddRequest struct {
	// TemporaryName is the temporary name to use to access the bundle. The chunks must have
	// previously been created by using `BundleWriteRequest`.
	TemporaryName string `json:"temporary_name"`
	// ManifestHash is the expected hash of the manifest contained inside the bundle.
	ManifestHash hash.Hash `json:"manifest_hash"`
	// Labels are the labels to tag the bundle with so it can later be found.
	Labels map[string]string `json:"labels"`
	// Volumes are the volumes to attach to the bundle.
	Volumes map[string]string `json:"volumes"`
}

// BundleAddResponse is the response from the BundleAdd method.
type BundleAddResponse struct{}

// BundleRemoveRequest is a request to host to remove specific bundles.
//
// The `PermissionBundleRemove` permission is required to call this method.
type BundleRemoveRequest struct {
	// Labels are the labels to filter the bundles by. All labels must match.
	Labels map[string]string `json:"labels"`
}

// BundleRemoveResponse is the response from the BundleRemove method.
type BundleRemoveResponse struct{}

// BundleListRequest is a request to host to list all bundles.
//
// The `PermissionBundleAdd` permission is required to call this method.
type BundleListRequest struct {
	// Labels are the labels to filter the bundles by. All labels must match.
	Labels map[string]string `json:"labels"`
}

// BundleListResponse is a response from host to list all bundles.
type BundleListResponse struct {
	// Bundles are the resulting bundles.
	Bundles []*BundleInfo `json:"bundles,omitempty"`
}

// BundleInfo is the bundle information.
type BundleInfo struct {
	// ManifestHash is the hash of the manifest.
	ManifestHash hash.Hash `json:"manifest_hash"`
	// Components is a list of all components in this bundle.
	Components []*ComponentInfo `json:"components"`
	// Labels is a set of labels assigned to this bundle.
	Labels map[string]string `json:"labels,omitempty"`
}

// ComponentInfo is the component information.
type ComponentInfo struct {
	// Name is the component name.
	Name string `json:"name"`
}
