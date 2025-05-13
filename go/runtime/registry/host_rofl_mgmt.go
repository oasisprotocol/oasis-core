package registry

import (
	"context"
	"encoding/hex"
	"fmt"
	"maps"
	"path/filepath"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/tuplehash"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	runtimeConfig "github.com/oasisprotocol/oasis-core/go/runtime/config"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/log"
	rofl "github.com/oasisprotocol/oasis-core/go/runtime/rofl/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/volume"
)

// labelInstanceID is the name of the special label that identifies the instance.
const labelInstanceID = "net.oasis.instance_id"

// handleBundleManagement handles bundle management local RPCs.
func (rh *roflHostHandler) handleBundleManagement(rq *enclaverpc.Request) (any, error) {
	switch rq.Method {
	case rofl.MethodBundleWrite:
		// Write bundle data to temporary file.
		var args rofl.BundleWriteRequest
		if err := cbor.Unmarshal(rq.Args, &args); err != nil {
			return nil, err
		}
		return rh.handleBundleWrite(&args)
	case rofl.MethodBundleAdd:
		// Add a new bundle from a temporary file.
		var args rofl.BundleAddRequest
		if err := cbor.Unmarshal(rq.Args, &args); err != nil {
			return nil, err
		}
		return rh.handleBundleAdd(&args)
	case rofl.MethodBundleRemove:
		// Remove a previously added bundle.
		var args rofl.BundleRemoveRequest
		if err := cbor.Unmarshal(rq.Args, &args); err != nil {
			return nil, err
		}
		return rh.handleBundleRemove(&args)
	case rofl.MethodBundleList:
		// List all bundles that we have access to.
		var args rofl.BundleListRequest
		if err := cbor.Unmarshal(rq.Args, &args); err != nil {
			return nil, err
		}
		return rh.handleBundleList(&args)
	default:
		return nil, fmt.Errorf("method not supported")
	}
}

// handleVolumeManagement handles volume management local RPCs.
func (rh *roflHostHandler) handleVolumeManagement(rq *enclaverpc.Request) (any, error) {
	switch rq.Method {
	case rofl.MethodVolumeAdd:
		// Add a new volume.
		var args rofl.VolumeAddRequest
		if err := cbor.Unmarshal(rq.Args, &args); err != nil {
			return nil, err
		}
		return rh.handleVolumeAdd(&args)
	case rofl.MethodVolumeRemove:
		// Remove volumes.
		var args rofl.VolumeRemoveRequest
		if err := cbor.Unmarshal(rq.Args, &args); err != nil {
			return nil, err
		}
		return rh.handleVolumeRemove(&args)
	case rofl.MethodVolumeList:
		// List all volumes that we have access to.
		var args rofl.VolumeListRequest
		if err := cbor.Unmarshal(rq.Args, &args); err != nil {
			return nil, err
		}
		return rh.handleVolumeList(&args)
	default:
		return nil, fmt.Errorf("method not supported")
	}
}

// handleLogManagement handles log management local RPCs.
func (rh *roflHostHandler) handleLogManagement(ctx context.Context, rq *enclaverpc.Request) (any, error) {
	switch rq.Method {
	case rofl.MethodLogGet:
		// Get logs.
		var args rofl.LogGetRequest
		if err := cbor.Unmarshal(rq.Args, &args); err != nil {
			return nil, err
		}
		return rh.handleLogGet(ctx, &args)
	default:
		return nil, fmt.Errorf("method not supported")
	}
}

func (rh *roflHostHandler) handleBundleWrite(rq *rofl.BundleWriteRequest) (*rofl.BundleWriteResponse, error) {
	if err := rh.ensureComponentPermissions(runtimeConfig.PermissionBundleAdd); err != nil {
		return nil, err
	}

	tmpPath := rh.getBundleTemporaryPath(rq.TemporaryName)

	if err := rh.getBundleManager().WriteTemporary(tmpPath, rq.Create, rq.Data); err != nil {
		return nil, err
	}

	return &rofl.BundleWriteResponse{}, nil
}

func (rh *roflHostHandler) handleBundleAdd(rq *rofl.BundleAddRequest) (*rofl.BundleAddResponse, error) {
	if err := rh.ensureComponentPermissions(runtimeConfig.PermissionBundleAdd); err != nil {
		return nil, err
	}

	// Determine labels, make sure to override origin as that is used for isolation.
	labels := maps.Clone(rq.Labels)
	maps.Copy(labels, rh.getBundleManagementLabels())

	// Resolve volumes.
	volumes := make(map[string]*volume.Volume)
	for volName, volID := range rq.Volumes {
		volume, ok := rh.getVolumeManager().Get(volID)

		// Ensure volume exists and has the right labels.
		if !ok || !volume.HasLabels(rh.getBundleManagementLabels()) {
			return nil, fmt.Errorf("volume '%s' not found", volID)
		}

		volumes[volName] = volume
	}

	tmpPath := rh.getBundleTemporaryPath(rq.TemporaryName)
	opts := []bundle.AddOption{
		bundle.WithBundleManifestHash(rq.ManifestHash),
		bundle.WithBundleLabels(labels),
		bundle.WithManifestRewriter(managedManifestRewriter(labels)),
		bundle.WithBundleValidator(validateManagedBundle),
		bundle.WithBundleVolumes(volumes),
	}

	if err := rh.getBundleManager().AddTemporary(tmpPath, opts...); err != nil {
		return nil, err
	}

	// Remove temporary file after successful add.
	if err := rh.getBundleManager().RemoveTemporary(tmpPath); err != nil {
		return nil, err
	}

	return &rofl.BundleAddResponse{}, nil
}

func (rh *roflHostHandler) handleBundleRemove(rq *rofl.BundleRemoveRequest) (*rofl.BundleRemoveResponse, error) {
	if err := rh.ensureComponentPermissions(runtimeConfig.PermissionBundleRemove); err != nil {
		return nil, err
	}

	// Determine labels, make sure to override origin as that is used for isolation.
	labels := maps.Clone(rq.Labels)
	maps.Copy(labels, rh.getBundleManagementLabels())

	rh.getBundleManager().Remove(labels)

	return &rofl.BundleRemoveResponse{}, nil
}

func (rh *roflHostHandler) handleBundleList(rq *rofl.BundleListRequest) (*rofl.BundleListResponse, error) {
	if err := rh.ensureComponentPermissions(runtimeConfig.PermissionBundleAdd); err != nil {
		return nil, err
	}

	// Determine labels, make sure to override origin as that is used for isolation.
	labels := maps.Clone(rq.Labels)
	maps.Copy(labels, rh.getBundleManagementLabels())

	// Populate bundle information.
	var bundles []*rofl.BundleInfo
	for _, manifest := range rh.parent.env.GetRuntimeRegistry().GetBundleRegistry().ManifestsWithLabels(labels) {
		var bi rofl.BundleInfo
		bi.ManifestHash = manifest.Hash()
		bi.Labels = manifest.Labels

		for _, comp := range manifest.Components {
			bi.Components = append(bi.Components, &rofl.ComponentInfo{
				Name: comp.Name,
			})
		}

		bundles = append(bundles, &bi)
	}

	return &rofl.BundleListResponse{
		Bundles: bundles,
	}, nil
}

func (rh *roflHostHandler) handleVolumeAdd(rq *rofl.VolumeAddRequest) (*rofl.VolumeAddResponse, error) {
	if err := rh.ensureComponentPermissions(runtimeConfig.PermissionVolumeAdd); err != nil {
		return nil, err
	}

	// Determine labels, make sure to override origin as that is used for isolation.
	labels := maps.Clone(rq.Labels)
	maps.Copy(labels, rh.getBundleManagementLabels())

	volume, err := rh.getVolumeManager().Create(labels)
	if err != nil {
		return nil, err
	}

	return &rofl.VolumeAddResponse{
		ID: volume.ID,
	}, nil
}

func (rh *roflHostHandler) handleVolumeRemove(rq *rofl.VolumeRemoveRequest) (*rofl.VolumeRemoveResponse, error) {
	if err := rh.ensureComponentPermissions(runtimeConfig.PermissionVolumeRemove); err != nil {
		return nil, err
	}

	// Determine labels, make sure to override origin as that is used for isolation.
	labels := maps.Clone(rq.Labels)
	maps.Copy(labels, rh.getBundleManagementLabels())

	if err := rh.getVolumeManager().Remove(labels); err != nil {
		return nil, err
	}
	return &rofl.VolumeRemoveResponse{}, nil
}

func (rh *roflHostHandler) handleVolumeList(rq *rofl.VolumeListRequest) (*rofl.VolumeListResponse, error) {
	if err := rh.ensureComponentPermissions(runtimeConfig.PermissionVolumeAdd); err != nil {
		return nil, err
	}

	// Determine labels, make sure to override origin as that is used for isolation.
	labels := maps.Clone(rq.Labels)
	maps.Copy(labels, rh.getBundleManagementLabels())

	// Populate volume information.
	var volumes []*rofl.VolumeInfo
	for _, volume := range rh.getVolumeManager().Volumes(labels) {
		var vi rofl.VolumeInfo
		vi.ID = volume.ID
		vi.Labels = volume.Labels

		volumes = append(volumes, &vi)
	}

	return &rofl.VolumeListResponse{
		Volumes: volumes,
	}, nil
}

func (rh *roflHostHandler) handleLogGet(ctx context.Context, rq *rofl.LogGetRequest) (*rofl.LogGetResponse, error) {
	if err := rh.ensureComponentPermissions(runtimeConfig.PermissionLogView); err != nil {
		return nil, err
	}

	// Determine labels, make sure to override origin as that is used for isolation.
	labels := maps.Clone(rq.Labels)
	maps.Copy(labels, rh.getBundleManagementLabels())

	var requestedComponentID component.ID
	if err := requestedComponentID.UnmarshalText([]byte(rq.ComponentID)); err != nil {
		return nil, err
	}
	if requestedComponentID.IsRONL() {
		return nil, fmt.Errorf("RONL component not allowed")
	}

	// Ensure that the passed component is actually accessible using the given labels.
	found := false
	for _, manifest := range rh.parent.env.GetRuntimeRegistry().GetBundleRegistry().ManifestsWithLabels(labels) {
		_, found = manifest.GetComponentByID(requestedComponentID)
		if found {
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("component not found")
	}

	opts := log.WatchOptions{
		Follow: false,
		Since:  time.Unix(int64(rq.Since), 0),
	}

	log, err := rh.getLogManager().Get(rh.parent.runtime.ID(), requestedComponentID)
	if err != nil {
		return nil, err
	}

	// TODO: Support streaming logs.
	logs, err := log.Read(ctx, opts)
	if err != nil {
		return nil, err
	}

	return &rofl.LogGetResponse{
		Logs: logs,
	}, nil
}

// ensureComponentPermissions ensures that the component has all of the specified permissions.
func (rh *roflHostHandler) ensureComponentPermissions(perms ...runtimeConfig.ComponentPermission) error {
	compCfg, ok := config.GlobalConfig.Runtime.GetComponent(rh.parent.runtime.ID(), rh.id)
	if !ok {
		return fmt.Errorf("forbidden")
	}
	for _, perm := range perms {
		if !compCfg.HasPermission(perm) {
			return fmt.Errorf("forbidden")
		}
	}
	return nil
}

func (rh *roflHostHandler) getBundleManager() *bundle.Manager {
	return rh.parent.env.GetRuntimeRegistry().GetBundleManager()
}

func (rh *roflHostHandler) getVolumeManager() *volume.Manager {
	return rh.parent.env.GetRuntimeRegistry().GetVolumeManager()
}

func (rh *roflHostHandler) getLogManager() *log.Manager {
	return rh.parent.env.GetRuntimeRegistry().GetLogManager()
}

func (rh *roflHostHandler) getBundleManagementLabels() map[string]string {
	compID, _ := rh.id.MarshalText()

	return map[string]string{
		bundle.LabelOrigin: fmt.Sprintf("%s-%s", rh.parent.runtime.ID(), string(compID)),
	}
}

func (rh *roflHostHandler) getBundleTemporaryPath(tmpName string) string {
	dirName := rh.getBundleManagementLabels()[bundle.LabelOrigin]
	// Hash the origin to make sure it doesn't contain any characters that are not fs-friendly.
	dirName = hash.NewFromBytes([]byte(dirName)).Hex()
	return filepath.Join(dirName, tmpName)
}

func managedManifestRewriter(labels map[string]string) bundle.ManifestRewriterFunc {
	return func(manifest *bundle.Manifest) {
		manifest.Name = ""
		manifest.Version = version.Version{}

		// Rewrite all components.
		for _, comp := range manifest.Components {
			h := tuplehash.New256(32, []byte("oasis-core/bundle: dynamic component ID"))
			// Ensure components are isolated by origin.
			_, _ = h.Write([]byte(labels[bundle.LabelOrigin]))
			// Ensure components are isolated by instance.
			instanceID := labels[labelInstanceID]
			_, _ = h.Write([]byte(instanceID))
			// Ensure separation between multiple components on the same instance.
			_, _ = h.Write([]byte(comp.Name))

			// Rewrite component name.
			comp.Name = hex.EncodeToString(h.Sum(nil))
			// Clear component version to avoid the version interfering with the upgrade process.
			comp.Version = version.Version{}
		}
	}
}

func validateManagedBundle(bnd *bundle.Bundle) error {
	if bnd.Manifest.Executable != "" || bnd.Manifest.SGX != nil {
		return fmt.Errorf("legacy bundles are not supported")
	}
	for _, comp := range bnd.Manifest.Components {
		if comp.Kind != component.ROFL {
			return fmt.Errorf("non-ROFL components are not supported")
		}
		if comp.Executable != "" {
			return fmt.Errorf("legacy bundles are not supported")
		}
		if comp.Disabled {
			return fmt.Errorf("disabled components are not supported")
		}
	}
	return nil
}
