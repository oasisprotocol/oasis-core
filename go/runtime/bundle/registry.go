package bundle

import (
	"fmt"
	"maps"
	"slices"
	"sync"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/config"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
)

// CfgDebugMockIDs configures mock runtime IDs for the purpose of testing.
const CfgDebugMockIDs = "runtime.debug.mock_ids"

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// Registry is an interface for handling newly discovered bundles.
type Registry interface {
	// HasBundle returns true iff the registry has the bundle.
	HasBundle(manifestHash hash.Hash) bool

	// AddBundle adds a bundle from the given path.
	AddBundle(path string, manifestHash hash.Hash) error

	// GetVersions returns versions for the given runtime, sorted in ascending
	// order.
	GetVersions(runtimeID common.Namespace) []version.Version

	// WatchVersions provides a channel that streams runtime versions as they
	// are added to the registry.
	WatchVersions(runtimeID common.Namespace) (<-chan version.Version, *pubsub.Subscription)

	// GetManifests returns all known manifests that contain RONL component.
	GetManifests() []*Manifest

	// GetName returns optional human readable runtime name.
	GetName(runtimeID common.Namespace, version version.Version) (string, error)

	// GetComponents returns RONL component for the given runtime and version,
	// together with latest version of the remaining components.
	GetComponents(runtimeID common.Namespace, version version.Version) ([]*ExplodedComponent, error)
}

// registry is a registry of runtime bundle manifests and components.
type registry struct {
	mu sync.RWMutex

	dataDir string

	bundles    map[hash.Hash]struct{}
	manifests  map[common.Namespace]map[version.Version]*Manifest
	components map[common.Namespace]map[component.ID]map[version.Version]*ExplodedComponent
	notifiers  map[common.Namespace]*pubsub.Broker

	logger *logging.Logger
}

// NewRegistry creates a new bundle registry, using the given data directory
// to store the extracted bundle files.
func NewRegistry(dataDir string) Registry {
	logger := logging.GetLogger("runtime/bundle/registry")

	return &registry{
		dataDir:    dataDir,
		bundles:    make(map[hash.Hash]struct{}),
		manifests:  make(map[common.Namespace]map[version.Version]*Manifest),
		components: make(map[common.Namespace]map[component.ID]map[version.Version]*ExplodedComponent),
		notifiers:  make(map[common.Namespace]*pubsub.Broker),
		logger:     logger,
	}
}

// HasBundle implements Registry.
func (r *registry) HasBundle(manifestHash hash.Hash) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, ok := r.bundles[manifestHash]
	return ok
}

// AddBundle implements Registry.
func (r *registry) AddBundle(path string, manifestHash hash.Hash) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.logger.Info("adding bundle",
		"path", path,
		"manifest_hash", manifestHash,
	)

	// Open the bundle and release resources when done.
	bnd, err := Open(path, WithManifestHash(manifestHash))
	if err != nil {
		return fmt.Errorf("failed to open bundle '%s': %w", path, err)
	}
	defer bnd.Close()

	// Skip already processed bundles. This check should be performed
	// after the bundle is opened and its manifest hash is verified.
	if _, ok := r.bundles[manifestHash]; ok {
		return nil
	}

	// Ensure the manifest doesn't include a component version already
	// in the registry.
	components := bnd.Manifest.GetAvailableComponents()

	for compID, comp := range components {
		if _, ok := r.components[bnd.Manifest.ID][compID][comp.Version]; ok {
			return fmt.Errorf("duplicate component '%s', version '%s', for runtime '%s'",
				compID,
				comp.Version,
				bnd.Manifest.ID,
			)
		}
	}

	// Explode the bundle.
	explodedDataDir, err := bnd.WriteExploded(r.dataDir)
	if err != nil {
		return fmt.Errorf("failed to explode bundle '%s': %w", path, err)
	}

	// Add manifests containing RONL component to the registry.
	detached := true
	if ronl, ok := components[component.ID_RONL]; ok {
		detached = false

		rtManifests, ok := r.manifests[bnd.Manifest.ID]
		if !ok {
			rtManifests = make(map[version.Version]*Manifest)
			r.manifests[bnd.Manifest.ID] = rtManifests
		}

		rtManifests[ronl.Version] = bnd.Manifest

		if notifier, ok := r.notifiers[bnd.Manifest.ID]; ok {
			notifier.Broadcast(ronl.Version)
		}
	}

	// Add components to the registry.
	for compID, comp := range components {
		runtimeComponents, ok := r.components[bnd.Manifest.ID]
		if !ok {
			runtimeComponents = make(map[component.ID]map[version.Version]*ExplodedComponent)
			r.components[bnd.Manifest.ID] = runtimeComponents
		}

		componentVersions, ok := runtimeComponents[compID]
		if !ok {
			componentVersions = make(map[version.Version]*ExplodedComponent)
			runtimeComponents[compID] = componentVersions
		}

		componentVersions[comp.Version] = &ExplodedComponent{
			Component:       comp,
			Detached:        detached,
			ExplodedDataDir: explodedDataDir,
		}
	}

	// Remember which bundles were added.
	r.bundles[manifestHash] = struct{}{}

	r.logger.Info("bundle added",
		"path", path,
		"runtime_id", bnd.Manifest.ID,
		"manifest_hash", bnd.manifestHash,
	)

	return nil
}

// GetVersions implements Registry.
func (r *registry) GetVersions(runtimeID common.Namespace) []version.Version {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if cmdFlags.DebugDontBlameOasis() && viper.IsSet(CfgDebugMockIDs) {
		// Allow the mock provisioner to function, as it does not use an actual
		// runtime. This is only used for the basic node tests.
		return []version.Version{
			{Major: 0, Minor: 0, Patch: 0},
		}
	}

	versions := slices.Collect(maps.Keys(r.manifests[runtimeID]))
	slices.SortFunc(versions, version.Version.Cmp)

	return versions
}

// WatchVersions implements Registry.
func (r *registry) WatchVersions(runtimeID common.Namespace) (<-chan version.Version, *pubsub.Subscription) {
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

// GetManifests implements Registry.
func (r *registry) GetManifests() []*Manifest {
	r.mu.RLock()
	defer r.mu.RUnlock()

	manifests := make([]*Manifest, 0)
	for _, manifest := range r.manifests {
		manifests = slices.AppendSeq(manifests, maps.Values(manifest))
	}

	return manifests
}

// GetName implements Registry.
func (r *registry) GetName(runtimeID common.Namespace, version version.Version) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if cmdFlags.DebugDontBlameOasis() && viper.IsSet(CfgDebugMockIDs) {
		// Allow the mock provisioner to function, as it does not use an actual
		// runtime. This is only used for the basic node tests.
		return "mock-runtime", nil
	}

	manifest, ok := r.manifests[runtimeID][version]
	if !ok {
		return "", fmt.Errorf("manifest for runtime '%s', version '%s' not found", runtimeID, version)
	}

	return manifest.Name, nil
}

// GetComponents implements Registry.
func (r *registry) GetComponents(runtimeID common.Namespace, version version.Version) ([]*ExplodedComponent, error) {
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

func init() {
	Flags.StringSlice(CfgDebugMockIDs, nil, "Mock runtime IDs (format: <path>,<path>,...)")
	_ = Flags.MarkHidden(CfgDebugMockIDs)

	_ = viper.BindPFlags(Flags)
}
