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

// ComponentNotification is a component notification.
type ComponentNotification struct {
	// Added is set when the given component has been added.
	Added *ExplodedComponent
	// Removed is set when the given component has been removed.
	Removed *component.ID
}

// Registry is a registry of manifests and components.
type Registry struct {
	mu sync.RWMutex

	manifests  map[hash.Hash]*ExplodedManifest
	components map[common.Namespace]map[component.ID]map[version.Version]*ExplodedComponent
	notifiers  map[common.Namespace]*pubsub.Broker

	logger *logging.Logger
}

// NewRegistry creates a new registry of manifests and components.
func NewRegistry() *Registry {
	logger := logging.GetLogger("runtime/bundle/registry")

	return &Registry{
		manifests:  make(map[hash.Hash]*ExplodedManifest),
		components: make(map[common.Namespace]map[component.ID]map[version.Version]*ExplodedComponent),
		notifiers:  make(map[common.Namespace]*pubsub.Broker),
		logger:     logger,
	}
}

// HasManifest returns true iff the store already contains a manifest
// with the given hash.
func (r *Registry) HasManifest(hash hash.Hash) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, ok := r.manifests[hash]
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
	if _, ok := r.manifests[manifestHash]; ok {
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

	// Add components to the registry.
	detached := true
	if _, ok := components[component.ID_RONL]; ok {
		detached = false
	}

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
			hasSGXLoader := config.GlobalConfig.Runtime.SGX.Loader != ""
			hasSGXLoader = hasSGXLoader || config.GlobalConfig.Runtime.SGXLoader != ""
			insecureMock := config.GlobalConfig.Runtime.DebugMockTEE
			if comp.ID().IsRONL() && config.GlobalConfig.Mode.IsClientOnly() && isEnvAuto && !hasSGXLoader && !insecureMock {
				teeKind = component.TEEKindNone
			}
		}

		comp := &ExplodedComponent{
			Component:       comp,
			TEEKind:         teeKind,
			Detached:        detached,
			ExplodedDataDir: manifest.ExplodedDataDir,
			Labels:          manifest.Labels,
			Volumes:         manifest.Volumes,
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
		componentVersions[comp.Version] = comp

		if notifier, ok := r.notifiers[manifest.ID]; ok {
			notifier.Broadcast(&ComponentNotification{Added: comp})
		}
	}

	// Remember which manifests were added.
	r.manifests[manifestHash] = manifest

	r.logger.Info("manifest added",
		"name", manifest.Name,
		"hash", manifestHash,
	)

	return nil
}

// Manifests returns all known manifests.
func (r *Registry) Manifests() []*ExplodedManifest {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Collect(maps.Values(r.manifests))
}

// ManifestsWithLabels returns all manifests that have the specified labels set.
func (r *Registry) ManifestsWithLabels(labels map[string]string) []*ExplodedManifest {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// TODO: Index labels when there are a lot of manifests to manage.
	var manifests []*ExplodedManifest
	for _, manifest := range r.manifests {
		if !manifest.HasLabels(labels) {
			continue
		}
		manifests = append(manifests, manifest)
	}
	return manifests
}

// RemoveManifest removes a manifest with provided hash.
func (r *Registry) RemoveManifest(hash hash.Hash) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.removeManifestLocked(hash)
}

func (r *Registry) removeManifestLocked(hash hash.Hash) bool {
	r.logger.Info("removing manifest",
		"manifest_hash", hash,
	)

	manifest, ok := r.manifests[hash]
	if !ok {
		return false
	}

	delete(r.manifests, hash)

	for _, c := range manifest.Manifest.Components {
		delete(r.components[manifest.ID][c.ID()], c.Version)
		if len(r.components[manifest.ID][c.ID()]) == 0 {
			delete(r.components[manifest.ID], c.ID())

			if notifier, ok := r.notifiers[manifest.ID]; ok {
				compID := c.ID()
				notifier.Broadcast(&ComponentNotification{Removed: &compID})
			}
		}
	}
	if len(r.components[manifest.ID]) == 0 {
		delete(r.components, manifest.ID)
	}

	return true
}

// RemoveManifestsWithLabels removes all manifests matching the provided labels.
//
// Returns the number of removed manifests.
func (r *Registry) RemoveManifestsWithLabels(labels map[string]string) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	// TODO: Index labels when there are a lot of manifests to manage.
	var result int
	for manifestHash, manifest := range r.manifests {
		if !manifest.HasLabels(labels) {
			continue
		}
		if r.removeManifestLocked(manifestHash) {
			result++
		}
	}
	return result
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

	versions := make([]version.Version, 0)
	for _, manifest := range r.manifests {
		if manifest.ID != runtimeID {
			continue
		}
		ronl, ok := manifest.GetComponentByID(component.ID_RONL)
		if !ok {
			continue
		}
		versions = append(versions, ronl.Version)
	}
	slices.SortFunc(versions, version.Version.Cmp)

	return versions
}

// Components returns all components for the given runtime.
func (r *Registry) Components(runtimeID common.Namespace) []*ExplodedComponent {
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
		}
	}

	var components []*ExplodedComponent
	for _, comps := range r.components[runtimeID] {
		for _, comp := range comps {
			components = append(components, comp)
		}
	}

	slices.SortFunc(components, func(a, b *ExplodedComponent) int {
		switch {
		case a.Component.Kind < b.Component.Kind:
			return -1
		case a.Component.Kind > b.Component.Kind:
			return 1
		default:
		}

		switch {
		case a.Component.Name < b.Component.Name:
			return -1
		case a.Component.Name > b.Component.Name:
			return 1
		default:
		}

		return a.Version.Cmp(b.Version)
	})

	return components
}

// WatchComponents provides a channel that streams runtime components as they
// are added to the registry.
func (r *Registry) WatchComponents(runtimeID common.Namespace) (<-chan *ComponentNotification, *pubsub.Subscription) {
	r.mu.Lock()
	defer r.mu.Unlock()

	notifier, ok := r.notifiers[runtimeID]
	if !ok {
		notifier = pubsub.NewBroker(false)
		r.notifiers[runtimeID] = notifier
	}

	sub := notifier.Subscribe()
	ch := make(chan *ComponentNotification)
	sub.Unwrap(ch)

	return ch, sub
}
