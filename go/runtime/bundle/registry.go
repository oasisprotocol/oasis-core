package bundle

import (
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/config"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	rtConfig "github.com/oasisprotocol/oasis-core/go/runtime/config"
)

// Registry is a registry of manifests and components.
type Registry struct {
	mu sync.RWMutex

	manifestHashes   map[hash.Hash]struct{}
	regularManifests map[common.Namespace]map[version.Version]*ExplodedManifest
	components       map[common.Namespace]map[component.ID]map[version.Version]*ExplodedComponent
	notifiers        map[common.Namespace]*pubsub.Broker

	logger *logging.Logger
}

// NewRegistry creates a new registry of manifests and components.
func NewRegistry() *Registry {
	logger := logging.GetLogger("runtime/bundle/registry")

	return &Registry{
		manifestHashes:   make(map[hash.Hash]struct{}),
		regularManifests: make(map[common.Namespace]map[version.Version]*ExplodedManifest),
		components:       make(map[common.Namespace]map[component.ID]map[version.Version]*ExplodedComponent),
		notifiers:        make(map[common.Namespace]*pubsub.Broker),
		logger:           logger,
	}
}

// HasManifest returns true iff the store already contains a manifest
// with the given hash.
func (r *Registry) HasManifest(hash hash.Hash) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, ok := r.manifestHashes[hash]
	return ok
}

// AddManifest adds the provided exploded manifest to the store.
func (r *Registry) AddManifest(manifest *ExplodedManifest) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	manifestHash := manifest.Hash()

	r.logger.Info("adding manifest",
		"name", manifest.Name,
		"hash", manifestHash,
	)

	// Skip already processed manifests.
	if _, ok := r.manifestHashes[manifestHash]; ok {
		return nil
	}

	// Ensure the manifest doesn't include a component version already
	// in the registry.
	components := manifest.GetAvailableComponents()
	for compID, comp := range components {
		if _, ok := r.components[manifest.ID][compID][comp.Version]; ok {
			return fmt.Errorf("duplicate component '%s', version '%s', for runtime '%s'",
				compID,
				comp.Version,
				manifest.ID,
			)
		}
	}

	// Add manifests containing RONL component to the registry.
	detached := true
	if ronl, ok := components[component.ID_RONL]; ok {
		detached = false

		rtManifests, ok := r.regularManifests[manifest.ID]
		if !ok {
			rtManifests = make(map[version.Version]*ExplodedManifest)
			r.regularManifests[manifest.ID] = rtManifests
		}

		rtManifests[ronl.Version] = manifest

		if notifier, ok := r.notifiers[manifest.ID]; ok {
			notifier.Broadcast(ronl.Version)
		}
	}

	// Add components to the registry.
	for compID, comp := range components {
		teeKind := comp.TEEKind()
		if compCfg, ok := config.GlobalConfig.Runtime.GetComponent(manifest.ID, compID); ok {
			if kind, ok := compCfg.TEEKind(); ok {
				teeKind = kind
			}
		} else {
			// Support legacy configuration where the runtime environment determines
			// whether the client node should run the runtime in an SGX environment.
			isEnvAuto := config.GlobalConfig.Runtime.Environment == rtConfig.RuntimeEnvironmentAuto
			hasSGXLoader := config.GlobalConfig.Runtime.SGXLoader != ""
			insecureMock := config.GlobalConfig.Runtime.DebugMockTEE
			if comp.ID().IsRONL() && config.GlobalConfig.Mode.IsClientOnly() && isEnvAuto && !hasSGXLoader && !insecureMock {
				teeKind = component.TEEKindNone
			}
		}

		runtimeComponents, ok := r.components[manifest.ID]
		if !ok {
			runtimeComponents = make(map[component.ID]map[version.Version]*ExplodedComponent)
			r.components[manifest.ID] = runtimeComponents
		}

		componentVersions, ok := runtimeComponents[compID]
		if !ok {
			componentVersions = make(map[version.Version]*ExplodedComponent)
			runtimeComponents[compID] = componentVersions
		}

		componentVersions[comp.Version] = &ExplodedComponent{
			Component:       comp,
			TEEKind:         teeKind,
			Detached:        detached,
			ExplodedDataDir: manifest.ExplodedDataDir,
		}
	}

	// Remember which manifests were added.
	r.manifestHashes[manifestHash] = struct{}{}

	r.logger.Info("manifest added",
		"name", manifest.Name,
		"hash", manifestHash,
	)

	return nil
}

// GetVersions returns versions for the given runtime, sorted in ascending
// order.
func (r *Registry) GetVersions(runtimeID common.Namespace) []version.Version {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if cmdFlags.DebugDontBlameOasis() && viper.IsSet(CfgDebugMockIDs) {
		// Allow the mock provisioner to function, as it does not use an actual
		// runtime. This is only used for the basic node tests.
		return []version.Version{
			{Major: 0, Minor: 0, Patch: 0},
		}
	}

	versions := slices.Collect(maps.Keys(r.regularManifests[runtimeID]))
	slices.SortFunc(versions, version.Version.Cmp)

	return versions
}

// WatchVersions provides a channel that streams runtime versions as they
// are added to the registry.
func (r *Registry) WatchVersions(runtimeID common.Namespace) (<-chan version.Version, *pubsub.Subscription) {
	r.mu.Lock()
	defer r.mu.Unlock()

	notifier, ok := r.notifiers[runtimeID]
	if !ok {
		notifier = pubsub.NewBroker(false)
		r.notifiers[runtimeID] = notifier
	}

	sub := notifier.Subscribe()
	ch := make(chan version.Version)
	sub.Unwrap(ch)

	return ch, sub
}

// GetManifests returns all known exploded manifests that contain RONL component.
func (r *Registry) GetManifests() []*ExplodedManifest {
	r.mu.RLock()
	defer r.mu.RUnlock()

	manifests := make([]*ExplodedManifest, 0)
	for _, manifest := range r.regularManifests {
		manifests = slices.AppendSeq(manifests, maps.Values(manifest))
	}

	return manifests
}

// GetName returns optional human readable runtime name.
func (r *Registry) GetName(runtimeID common.Namespace, version version.Version) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if cmdFlags.DebugDontBlameOasis() && viper.IsSet(CfgDebugMockIDs) {
		// Allow the mock provisioner to function, as it does not use an actual
		// runtime. This is only used for the basic node tests.
		return "mock-runtime", nil
	}

	manifest, ok := r.regularManifests[runtimeID][version]
	if !ok {
		return "", fmt.Errorf("manifest for runtime '%s', version '%s' not found", runtimeID, version)
	}

	return manifest.Name, nil
}

// GetComponents returns RONL component for the given runtime and version,
// together with latest version of the remaining components.
func (r *Registry) GetComponents(runtimeID common.Namespace, version version.Version) ([]*ExplodedComponent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if cmdFlags.DebugDontBlameOasis() && viper.IsSet(CfgDebugMockIDs) {
		// Allow the mock provisioner to function, as it does not use an actual
		// runtime. This is only used for the basic node tests.
		return []*ExplodedComponent{
			{
				Component: &Component{
					Kind: component.RONL,
					ELF: &ELFMetadata{
						Executable: "mock",
					},
				},
				Detached: false,
			},
		}, nil
	}

	// Prepare function to determine what kind of components we want.
	isComponentWanted := func(compID component.ID, comp *ExplodedComponent) bool {
		// Skip the RONL component, as the exact version is added manually.
		if compID.IsRONL() {
			return false
		}

		// Node configuration overrides all other settings.
		if compCfg, ok := config.GlobalConfig.Runtime.GetComponent(runtimeID, compID); ok {
			return !compCfg.Disabled
		}

		// Detached components are explicit and they should be enabled by default.
		if comp.Detached {
			return true
		}

		// On non-compute nodes, assume all components are disabled by default.
		if config.GlobalConfig.Mode != config.ModeCompute {
			return false
		}

		// By default honor the status of the component itself.
		return !comp.Disabled
	}

	// Collect all components into a slice.
	components := make([]*ExplodedComponent, 0, 1)

	// Add the specified version of the RONL component.
	ronl, ok := r.components[runtimeID][component.ID_RONL][version]
	if !ok {
		return nil, fmt.Errorf("component '%s', version '%s', for runtime '%s' not found", component.RONL, version, runtimeID)
	}
	components = append(components, ronl)

	// Add the latest version of the remaining components.
	for compID, runtimeComponents := range r.components[runtimeID] {
		var latestVersion uint64
		var latestComp *ExplodedComponent

		for version, comp := range runtimeComponents {
			// Skip if the version is not the highest.
			if version.ToU64() < latestVersion {
				continue
			}

			// Skip if the component is not wanted.
			if !isComponentWanted(compID, comp) {
				continue
			}

			latestVersion = version.ToU64()
			latestComp = comp
		}

		if latestComp != nil {
			components = append(components, latestComp)
		}

	}

	return components, nil
}
