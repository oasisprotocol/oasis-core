package registry

import (
	"context"
	"fmt"
	"maps"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	runtimeConfig "github.com/oasisprotocol/oasis-core/go/runtime/config"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
	rofl "github.com/oasisprotocol/oasis-core/go/runtime/rofl/api"
)

// handleBundleManagement handles bundle management local RPCs.
func (rh *roflHostHandler) handleBundleManagement(ctx context.Context, rq *enclaverpc.Request) (interface{}, error) {
	switch rq.Method {
	case rofl.MethodBundleWrite:
		// Write bundle data to temporary file.
		var args rofl.BundleWriteRequest
		if err := cbor.Unmarshal(rq.Args, &args); err != nil {
			return nil, err
		}
		return rh.handleBundleWrite(ctx, &args)
	case rofl.MethodBundleAdd:
		// Add a new bundle, previously written to via `HostBundleWriteRequest`.
		var args rofl.BundleAddRequest
		if err := cbor.Unmarshal(rq.Args, &args); err != nil {
			return nil, err
		}
		return rh.handleBundleAdd(ctx, &args)
	case rofl.MethodBundleRemove:
		// Remove a previously added bundle.
		var args rofl.BundleRemoveRequest
		if err := cbor.Unmarshal(rq.Args, &args); err != nil {
			return nil, err
		}
		return rh.handleBundleRemove(ctx, &args)
	case rofl.MethodBundleList:
		// List all bundles that we have access to.
		var args rofl.BundleListRequest
		if err := cbor.Unmarshal(rq.Args, &args); err != nil {
			return nil, err
		}
		return rh.handleBundleList(ctx, &args)
	default:
		return nil, fmt.Errorf("method not supported")
	}
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

func (rh *roflHostHandler) getBundleManagementLabels() map[string]string {
	compID, _ := rh.id.MarshalText()

	return map[string]string{
		bundle.LabelOrigin: fmt.Sprintf("%s-%s", rh.parent.runtime.ID(), string(compID)),
	}
}

func (rh *roflHostHandler) handleBundleWrite(_ context.Context, rq *rofl.BundleWriteRequest) (*rofl.BundleWriteResponse, error) {
	if err := rh.ensureComponentPermissions(runtimeConfig.PermissionBundleAdd); err != nil {
		return nil, err
	}

	labels := rh.getBundleManagementLabels()

	if err := rh.getBundleManager().WriteTemporary(rq.TemporaryName, labels, rq.Create, rq.Data); err != nil {
		return nil, err
	}

	return &rofl.BundleWriteResponse{}, nil
}

func (rh *roflHostHandler) handleBundleAdd(_ context.Context, rq *rofl.BundleAddRequest) (*rofl.BundleAddResponse, error) {
	if err := rh.ensureComponentPermissions(runtimeConfig.PermissionBundleAdd); err != nil {
		return nil, err
	}

	// Determine labels, make sure to override origin as that is used for isolation.
	labels := rq.Labels
	maps.Copy(labels, rh.getBundleManagementLabels())

	if err := rh.getBundleManager().AddTemporary(rq.TemporaryName, labels); err != nil {
		return nil, err
	}
	return &rofl.BundleAddResponse{}, nil
}

func (rh *roflHostHandler) handleBundleRemove(_ context.Context, rq *rofl.BundleRemoveRequest) (*rofl.BundleRemoveResponse, error) {
	if err := rh.ensureComponentPermissions(runtimeConfig.PermissionBundleRemove); err != nil {
		return nil, err
	}

	// Determine labels, make sure to override origin as that is used for isolation.
	labels := rq.Labels
	maps.Copy(labels, rh.getBundleManagementLabels())

	if err := rh.getBundleManager().Remove(labels); err != nil {
		return nil, err
	}
	return &rofl.BundleRemoveResponse{}, nil
}

func (rh *roflHostHandler) handleBundleList(_ context.Context, rq *rofl.BundleListRequest) (*rofl.BundleListResponse, error) {
	if err := rh.ensureComponentPermissions(runtimeConfig.PermissionBundleAdd); err != nil {
		return nil, err
	}

	// Determine labels, make sure to override origin as that is used for isolation.
	labels := rq.Labels
	maps.Copy(labels, rh.getBundleManagementLabels())

	// Populate bundle information.
	var bundles []*rofl.BundleInfo
	for _, manifest := range rh.parent.env.GetRuntimeRegistry().GetBundleRegistry().ManifestsWithLabels(labels) {
		var bi rofl.BundleInfo
		bi.ManifestHash = manifest.Hash()
		bi.Labels = maps.Clone(manifest.Labels)

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
