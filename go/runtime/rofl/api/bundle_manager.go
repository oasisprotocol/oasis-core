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
	// MethodBundleWipeStorage is the name of the BundleWipeStorage method.
	MethodBundleWipeStorage = "BundleWipeStorage"
	// MethodBundleList is the name of the BundleList method.
	MethodBundleList = "BundleList"
)

// BundleWriteRequest is a request to host to write a chunk of the bundle to a temporary file.
//
// The `PermissionBundleAdd` permission is required to call this method.
type BundleWriteRequest struct {
	// TemporaryName is the temporary file name to use on the host while writing the bundle.
	TemporaryName string `json:"temporary_name"`
	// Create is the optional flag which specifies that the temporary file should be recreated. If
	// the file exists and this flag is set to true, it will be truncated. If the flag is set to
	// false, any content will be appended to the existing file.
	Create bool `json:"create,omitempty"`
	// Data that should be appended to the temporary file.
	Data []byte `json:"data"`
}

// BundleWriteResponse is the response form the BundleWrite method.
type BundleWriteResponse struct{}

// BundleAddRequest is a request to host to add a specific bundle to the host.
//
// The `PermissionBundleAdd` permission is required to call this method.
type BundleAddRequest struct {
	// TemporaryName is the temporary file name to read the bundle from. The file must have
	// previously been created by using `BundleWriteRequest`.
	//
	// The file must be a valid bundle.
	TemporaryName string `json:"temporary_name"`
	// ManifestHash is the expected hash of the manifest contained inside the bundle.
	ManifestHash hash.Hash `json:"manifest_hash"`
	// Labels are the labels to tag the bundle with.
	//
	// Note that the host will assign a random component identifier to these components, so one
	// should use labels to later be able to find them.
	//
	// Use the special `LabelInstanceID` label to specify a deterministic instance ID.
	Labels map[string]string `json:"labels"`
}

// BundleAddResponse is the response form the BundleAdd method.
type BundleAddResponse struct{}

// BundleRemoveRequest is a request to host to remove a specific component. Only components added by
// this component can be removed.
//
// The `PermissionBundleRemove` permission is required to call this method.
type BundleRemoveRequest struct {
	// Labels are the labels to filter the components by.
	Labels map[string]string `json:"labels"`
}

// BundleRemoveResponse is the response form the BundleRemove method.
type BundleRemoveResponse struct{}

// BundleWipeStorageRequest is a request to wipe storage of all components in a bundle. Only
// components added by this component can be removed.
//
// The `PermissionBundleRemove` permission is required to call this method.
type BundleWipeStorageRequest struct {
	// Labels are the labels to filter the components by.
	Labels map[string]string `json:"labels"`
}

// BundleWipeStorageResponse is the response from the BundleWipeStorage method.
type BundleWipeStorageResponse struct{}

// BundleListRequest is a request to host to list all bundles.
//
// The `PermissionBundleAdd` permission is required to call this method.
type BundleListRequest struct {
	// Labels are the labels to filter the components by.
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
