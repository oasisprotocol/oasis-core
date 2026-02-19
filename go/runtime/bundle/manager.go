package bundle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	cmSync "github.com/oasisprotocol/oasis-core/go/common/sync"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	"github.com/oasisprotocol/oasis-core/go/runtime/volume"
)

const (
	// retryInterval is the time interval between failed bundle downloads.
	retryInterval = 15 * time.Minute

	// requestTimeout is the time limit for http client requests.
	requestTimeout = time.Minute

	// maxMetadataSizeBytes is the maximum allowed metadata size in bytes.
	maxMetadataSizeBytes = 2 * 1024 // 2 KB

	// maxDefaultBundleSizeBytes is the maximum allowed default bundle size
	// in bytes.
	maxDefaultBundleSizeBytes = 20 * 1024 * 1024 // 20 MB

	// maxLabelSize is the maximum size of a single label key or value.
	maxLabelSize = 1024
	// maxLabelCount is the maximum number of labels.
	maxLabelCount = 1024
)

// ManifestStore is an interface that defines methods for storing exploded manifests.
type ManifestStore interface {
	// HasManifest returns true iff the store already contains an exploded manifest
	// with the given hash.
	HasManifest(hash hash.Hash) bool

	// AddManifest adds the provided exploded manifest to the store.
	AddManifest(manifest *ExplodedManifest) error

	// RemoveManifest removes an exploded manifest with provided hash.
	RemoveManifest(hash hash.Hash) bool

	// RemoveManifestsWithLabels removes all manifests matching the provided labels.
	//
	// Returns the number of removed manifests.
	RemoveManifestsWithLabels(labels map[string]string) int

	// Manifests returns all known exploded manifests.
	Manifests() []*ExplodedManifest
}

// VolumeManager is an interface that defines methods for managing volumes.
type VolumeManager interface {
	// GetOrCreate retrieves the first volume matching given labels or creates a new one.
	GetOrCreate(labels map[string]string) (*volume.Volume, error)
}

// ValidatorFunc is a function that validates a bundle.
type ValidatorFunc func(*Bundle) error

// AddOptions are options for adding bundles.
type AddOptions struct {
	labels           map[string]string
	manifestHash     *hash.Hash
	manifestRewriter ManifestRewriterFunc
	validator        ValidatorFunc
	volumes          map[string]*volume.Volume
}

// NewAddOptions creates options using default and given values.
func NewAddOptions(opts ...AddOption) *AddOptions {
	var o AddOptions
	for _, opt := range opts {
		opt(&o)
	}
	return &o
}

// AddOption is an option used when adding a bundle.
type AddOption func(o *AddOptions)

// WithBundleLabels sets the bundle labels.
func WithBundleLabels(labels map[string]string) AddOption {
	return func(o *AddOptions) {
		o.labels = labels
	}
}

// WithBundleManifestHash sets the manifest hash to validate when adding a bundle.
func WithBundleManifestHash(h hash.Hash) AddOption {
	return func(o *AddOptions) {
		o.manifestHash = &h
	}
}

// WithManifestRewriter sets the manifest rewriter function.
func WithManifestRewriter(f ManifestRewriterFunc) AddOption {
	return func(o *AddOptions) {
		o.manifestRewriter = f
	}
}

// WithBundleValidator sets the bundle validator function.
func WithBundleValidator(f ValidatorFunc) AddOption {
	return func(o *AddOptions) {
		o.validator = f
	}
}

// WithBundleVolumes sets the bundle volumes to attach.
func WithBundleVolumes(volumes map[string]*volume.Volume) AddOption {
	return func(o *AddOptions) {
		o.volumes = volumes
	}
}

// Manager is responsible for managing bundles.
type Manager struct {
	mu       sync.RWMutex
	startOne cmSync.One

	dataDir            string
	bundleDir          string
	tmpBundleDir       string
	maxBundleSizeBytes int64

	runtimeIDs map[common.Namespace]struct{}

	runtimeBaseURLs map[common.Namespace][]string
	globalBaseURLs  []string

	triggerCh     chan struct{}
	downloadQueue map[common.Namespace][]hash.Hash
	cleanupQueue  map[common.Namespace]version.Version

	client        *http.Client
	store         ManifestStore
	volumeManager VolumeManager

	logger logging.Logger
}

// NewManager creates a new bundle manager.
func NewManager(dataDir string, runtimeIDs []common.Namespace, store ManifestStore, volumeManager VolumeManager) (*Manager, error) {
	logger := logging.GetLogger("runtime/bundle/manager")

	// Configure the HTTP client with a reasonable timeout.
	client := http.Client{
		Timeout: requestTimeout,
	}

	// Define a limit on the maximum allowed bundle size.
	bundleSize := int64(maxDefaultBundleSizeBytes)
	if size := config.GlobalConfig.Runtime.MaxBundleSize; size != "" {
		bundleSize = int64(config.ParseSizeInBytes(size))
	}

	// Validate global repository URLs.
	globalBaseURLs, err := validateAndNormalizeURLs(config.GlobalConfig.Runtime.Registries)
	if err != nil {
		return nil, err
	}

	// Validate each runtime's registry URLs.
	runtimeBaseURLs := make(map[common.Namespace][]string)
	for _, runtime := range config.GlobalConfig.Runtime.Runtimes {
		urls, err := validateAndNormalizeURLs(runtime.Registries)
		if err != nil {
			return nil, err
		}
		if len(urls) == 0 {
			continue
		}
		runtimeBaseURLs[runtime.ID] = urls
	}

	// Remember which runtimes to follow.
	runtimes := make(map[common.Namespace]struct{})
	for _, runtimeID := range runtimeIDs {
		runtimes[runtimeID] = struct{}{}
	}

	return &Manager{
		startOne:           cmSync.NewOne(),
		dataDir:            dataDir,
		bundleDir:          ExplodedPath(dataDir),
		tmpBundleDir:       TmpBundlePath(dataDir),
		maxBundleSizeBytes: bundleSize,
		runtimeIDs:         runtimes,
		globalBaseURLs:     globalBaseURLs,
		runtimeBaseURLs:    runtimeBaseURLs,
		triggerCh:          make(chan struct{}, 1),
		downloadQueue:      make(map[common.Namespace][]hash.Hash),
		cleanupQueue:       make(map[common.Namespace]version.Version),
		client:             &client,
		store:              store,
		volumeManager:      volumeManager,
		logger:             *logger,
	}, nil
}

// Start starts the bundle manager.
func (m *Manager) Start() {
	m.startOne.TryStart(m.run)
}

// Stop halts the bundle manager.
func (m *Manager) Stop() {
	m.startOne.TryStop()
}

func (m *Manager) run(ctx context.Context) {
	m.logger.Info("starting")

	// Cleanup temporary bundle directory and make sure it exists.
	if err := os.RemoveAll(m.tmpBundleDir); err != nil {
		m.logger.Error("failed to remove temporary bundle directory",
			"err", err,
		)
		return
	}
	if err := common.Mkdir(m.tmpBundleDir); err != nil {
		m.logger.Error("failed to create temporary bundle directory",
			"err", err,
		)
		return
	}

	// Ensure the bundle directory exists.
	if err := common.Mkdir(m.bundleDir); err != nil {
		m.logger.Error("failed to create bundle directory",
			"err", err,
			"dir", m.bundleDir,
		)
		return
	}

	// Extract bundles from the configuration.
	exploded, err := m.explodeBundles(config.GlobalConfig.Runtime.Paths)
	if err != nil {
		m.logger.Error("failed to explode bundles",
			"err", err,
		)
		return
	}

	// Load all manifests from the bundle directory.
	manifests, err := m.loadManifests()
	if err != nil {
		m.logger.Error("failed to load manifests",
			"err", err,
		)
		return
	}

	// Remove unneeded bundles and update the manifest map accordingly.
	manifests, err = m.cleanOnStartup(manifests, exploded)
	if err != nil {
		m.logger.Error("failed to cleanup bundles",
			"err", err,
		)
		return
	}

	// Register the remaining manifests in the registry.
	err = m.registerManifests(manifests)
	if err != nil {
		m.logger.Error("failed to register manifests",
			"err", err,
		)
		return
	}

	// Start the main task responsible for managing bundles.
	ticker := time.NewTicker(retryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
		case <-m.triggerCh:
		case <-ctx.Done():
			m.logger.Info("stopping")
			return
		}

		m.download()
		m.clean()
	}
}

// Add adds a bundle from the given path.
func (m *Manager) Add(path string, opts ...AddOption) error {
	manifest, err := m.explodeBundle(path, opts...)
	if err != nil {
		m.logger.Error("failed to explode bundle",
			"err", err,
			"path", path,
		)
		return err
	}

	if manifest.ID.IsKeyManager() {
		if err = m.removeBundle(manifest.ExplodedDataDir); err != nil {
			m.logger.Error("failed to remove bundle",
				"err", err,
				"path", path,
			)
		}
		m.logger.Warn("not allowed to add key manager bundle")
		return fmt.Errorf("not allowed to add key manager bundle")
	}

	if err := m.registerManifest(manifest); err != nil {
		m.logger.Error("failed to register manifest",
			"err", err,
		)
		return fmt.Errorf("failed to register manifest: %w", err)
	}

	return nil
}

// AddTemporary adds a bundle from the given temporary bundle file.
func (m *Manager) AddTemporary(tmpPath string, opts ...AddOption) error {
	tmpName, root, err := m.openTemporaryBundleRoot(tmpPath)
	if err != nil {
		return err
	}
	defer root.Close()

	fi, err := root.Stat(tmpName)
	if err != nil {
		return err
	}
	path := filepath.Join(root.Name(), fi.Name())

	return m.Add(path, opts...)
}

// Remove removes bundles matching the given labels.
func (m *Manager) Remove(labels map[string]string) {
	if err := validateLabels(labels); err != nil {
		return
	}

	m.store.RemoveManifestsWithLabels(labels)
}

// WriteTemporary writes the given data to a temporary file that can later be referenced as a
// bundle.
func (m *Manager) WriteTemporary(tmpPath string, create bool, data []byte) error {
	tmpName, root, err := m.openTemporaryBundleRoot(tmpPath)
	if err != nil {
		return err
	}
	defer root.Close()

	var mode int
	switch create {
	case true:
		mode = os.O_CREATE | os.O_TRUNC | os.O_WRONLY
	case false:
		mode = os.O_APPEND | os.O_WRONLY
	}

	f, err := root.OpenFile(tmpName, mode, 0o600)
	if err != nil {
		m.logger.Error("failed to open temporary bundle",
			"err", err,
		)
		return fmt.Errorf("failed to open temporary bundle")
	}
	defer f.Close()

	_, err = f.Write(data)
	return err
}

// RemoveTemporary removes the given temporary bundle file.
func (m *Manager) RemoveTemporary(tmpPath string) error {
	tmpName, root, err := m.openTemporaryBundleRoot(tmpPath)
	if err != nil {
		return err
	}
	defer root.Close()

	return root.Remove(tmpName)
}

// Download updates the checksums of bundles pending download for the given runtime.
//
// Any existing checksums in the download queue for the given runtime are removed
// and replaced with the given ones.
func (m *Manager) Download(runtimeID common.Namespace, manifestHashes []hash.Hash) {
	// Download bundles only for the configured runtimes.
	if _, ok := m.runtimeIDs[runtimeID]; !ok {
		return
	}

	// Key managers must configure the bundle statically to prevent
	// running different versions of the runtime.
	if runtimeID.IsKeyManager() {
		return
	}

	// Download bundles only if at least one endpoint is configured.
	if len(m.globalBaseURLs) == 0 && len(m.runtimeBaseURLs[runtimeID]) == 0 {
		return
	}

	// Update the queue.
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(manifestHashes) == 0 {
		delete(m.downloadQueue, runtimeID)
		return
	}
	m.downloadQueue[runtimeID] = manifestHashes

	// Trigger immediate download and clean-up of bundles.
	select {
	case m.triggerCh <- struct{}{}:
	default:
	}
}

// Cleanup updates the runtime's maximum bundle version for pending clean-up.
//
// If the specified runtime already exists in the cleanup queue,
// its version is updated only if the provided versions is greater.
//
// Warning: If clean-up fails it's not retried.
func (m *Manager) Cleanup(runtimeID common.Namespace, version version.Version) {
	// Key managers are allowed to run obsolete runtime versions.
	if runtimeID.IsKeyManager() {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if v, ok := m.cleanupQueue[runtimeID]; ok && !v.Less(version) {
		return
	}
	m.cleanupQueue[runtimeID] = version

	// Trigger immediate download and clean-up of bundles.
	select {
	case m.triggerCh <- struct{}{}:
	default:
	}
}

func (m *Manager) download() {
	m.logger.Info("downloading bundles")
	for runtimeID := range m.runtimeIDs {
		m.downloadBundles(runtimeID)
	}
}

func (m *Manager) downloadBundles(runtimeID common.Namespace) {
	// Try to download queued bundles.
	m.mu.RLock()
	hashes := m.downloadQueue[runtimeID]
	m.mu.RUnlock()

	downloaded := make(map[hash.Hash]struct{})
	for _, hash := range hashes {
		if err := m.downloadBundle(runtimeID, hash); err != nil {
			m.logger.Error("failed to download bundle",
				"err", err,
				"runtime_id", runtimeID,
				"manifest_hash", hash.Hex(),
			)
			continue
		}
		downloaded[hash] = struct{}{}
	}

	// Remove downloaded bundles from the queue.
	m.mu.Lock()
	defer m.mu.Unlock()

	var pending []hash.Hash
	for _, hash := range m.downloadQueue[runtimeID] {
		if _, ok := downloaded[hash]; ok {
			continue
		}
		pending = append(pending, hash)
	}
	if len(pending) == 0 {
		delete(m.downloadQueue, runtimeID)
		return
	}
	m.downloadQueue[runtimeID] = pending
}

func (m *Manager) downloadBundle(runtimeID common.Namespace, manifestHash hash.Hash) error {
	var errs error

	if m.store.HasManifest(manifestHash) {
		return nil
	}

	for _, baseURLs := range [][]string{m.runtimeBaseURLs[runtimeID], m.globalBaseURLs} {
		for _, baseURL := range baseURLs {
			if err := m.tryDownloadBundle(manifestHash, baseURL); err != nil {
				errs = errors.Join(errs, err)
				continue
			}

			return nil
		}
	}

	return errs
}

func (m *Manager) tryDownloadBundle(manifestHash hash.Hash, baseURL string) error {
	metaURL, err := url.JoinPath(baseURL, manifestHash.Hex())
	if err != nil {
		m.logger.Error("failed to construct metadata URL",
			"err", err,
		)
		return fmt.Errorf("failed to construct metadata URL: %w", err)
	}

	bundleURL, err := m.fetchMetadata(metaURL)
	if err != nil {
		m.logger.Error("failed to download metadata",
			"err", err,
			"url", metaURL,
		)
		return fmt.Errorf("failed to download metadata: %w", err)
	}

	bundleURL, err = validateAndNormalizeURL(bundleURL)
	if err != nil {
		return err
	}

	src, err := m.fetchBundle(bundleURL)
	if err != nil {
		m.logger.Error("failed to download bundle",
			"err", err,
			"url", metaURL,
		)
		return fmt.Errorf("failed to download bundle: %w", err)
	}
	defer os.Remove(src)

	manifest, err := m.explodeBundle(src, WithBundleManifestHash(manifestHash))
	if err != nil {
		m.logger.Error("failed to explode bundle",
			"err", err,
			"src", src,
		)
		return err
	}

	if err := m.registerManifest(manifest); err != nil {
		m.logger.Error("failed to register manifest",
			"err", err,
		)
		return fmt.Errorf("failed to register manifest: %w", err)
	}

	return nil
}

func (m *Manager) fetchMetadata(url string) (string, error) {
	m.logger.Info("downloading metadata",
		"url", url,
	)

	resp, err := m.client.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch metadata: invalid status code %d", resp.StatusCode)
	}

	limitedReader := io.LimitedReader{
		R: resp.Body,
		N: maxMetadataSizeBytes,
	}

	var buffer bytes.Buffer
	_, err = buffer.ReadFrom(&limitedReader)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("failed to read metadata content: %w", err)
	}
	metadata := strings.TrimSpace(buffer.String())

	m.logger.Info("metadata downloaded",
		"metadata", metadata,
	)

	return metadata, nil
}

func (m *Manager) fetchBundle(url string) (string, error) {
	m.logger.Info("downloading bundle",
		"url", url,
	)

	resp, err := m.client.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch bundle: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch bundle: invalid status code %d", resp.StatusCode)
	}

	// Copy to a temporary file as downloaded bundles are unverified.
	file, err := os.CreateTemp(m.tmpBundleDir, fmt.Sprintf("oasis-bundle-*%s", FileExtension))
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer func() {
		file.Close()
		if err != nil {
			_ = os.Remove(file.Name()) //nolint:gosec
		}
	}()

	limitedReader := io.LimitedReader{
		R: resp.Body,
		N: m.maxBundleSizeBytes,
	}

	if _, err = io.Copy(file, &limitedReader); err != nil {
		return "", fmt.Errorf("failed to save bundle: %w", err)
	}

	if limitedReader.N <= 0 {
		return "", fmt.Errorf("bundle exceeds size limit of %d bytes", m.maxBundleSizeBytes)
	}

	m.logger.Info("bundle downloaded",
		"url", url,
	)

	return file.Name(), nil
}

func (m *Manager) loadManifests() ([]*ExplodedManifest, error) {
	m.logger.Info("loading manifests")

	manifests := make([]*ExplodedManifest, 0)

	entries, err := os.ReadDir(m.bundleDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read bundle directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(m.bundleDir, entry.Name())

		b, err := os.ReadFile(filepath.Join(dir, manifestName))
		if err != nil {
			m.logger.Warn("skipping unreadable manifest",
				"path", dir,
				"err", err,
			)
			continue
		}

		var manifest Manifest
		if err = json.Unmarshal(b, &manifest); err != nil {
			m.logger.Warn("skipping malformed manifest",
				"path", dir,
				"err", err,
			)
			continue
		}

		m.logger.Info("manifest loaded",
			"name", manifest.Name,
			"hash", manifest.Hash(),
		)

		manifests = append(manifests, &ExplodedManifest{
			Manifest:        &manifest,
			ExplodedDataDir: dir,
		})
	}

	return manifests, nil
}

func (m *Manager) cleanOnStartup(manifests, exploded []*ExplodedManifest) ([]*ExplodedManifest, error) {
	m.logger.Info("cleaning bundles")

	explodedHashes := make(map[hash.Hash]struct{})
	for _, manifest := range exploded {
		explodedHashes[manifest.Hash()] = struct{}{}
	}

	shouldKeep := func(manifest *ExplodedManifest) bool {
		if _, ok := m.runtimeIDs[manifest.ID]; !ok {
			return false
		}
		if manifest.IsDetached() || manifest.ID.IsKeyManager() {
			if _, ok := explodedHashes[manifest.Hash()]; !ok {
				return false
			}
		}
		return true
	}

	retained := make([]*ExplodedManifest, 0)
	for _, manifest := range manifests {
		if shouldKeep(manifest) {
			retained = append(retained, manifest)
			continue
		}

		if err := m.removeBundle(manifest.ExplodedDataDir); err != nil {
			return nil, fmt.Errorf("failed to remove bundle: %w", err)
		}
	}

	return retained, nil
}

func (m *Manager) clean() {
	m.logger.Info("cleaning bundles")
	for runtimeID := range m.runtimeIDs {
		m.cleanBundles(runtimeID)
	}
}

func (m *Manager) cleanBundles(runtimeID common.Namespace) {
	maxVersion, ok := func() (version.Version, bool) {
		m.mu.Lock()
		defer m.mu.Unlock()

		maxVersion, ok := m.cleanupQueue[runtimeID]
		if !ok {
			return version.Version{}, false
		}
		delete(m.cleanupQueue, runtimeID)
		return maxVersion, true
	}()
	if !ok {
		return
	}

	m.logger.Info("cleaning bundles",
		"id", runtimeID,
		"max_version", maxVersion,
	)

	for _, manifest := range m.store.Manifests() {
		if manifest.ID != runtimeID {
			continue
		}

		ronl, ok := manifest.GetComponentByID(component.ID_RONL)
		if !ok {
			continue
		}
		if !ronl.Version.Less(maxVersion) {
			continue
		}

		m.cleanBundle(manifest)
	}
}

func (m *Manager) cleanBundle(manifest *ExplodedManifest) {
	m.logger.Info("cleaning bundle",
		"manifest_hash", manifest.Hash(),
	)

	if ok := m.store.RemoveManifest(manifest.Hash()); !ok {
		m.logger.Warn("failed to remove manifest from store",
			"manifest_hash", manifest.Hash(),
		)
	}

	if err := m.removeBundle(manifest.ExplodedDataDir); err != nil {
		m.logger.Error("failed to remove bundle",
			"err", err,
		)
	}
}

func (m *Manager) removeBundle(dir string) error {
	m.logger.Info("removing bundle",
		"dir", dir,
	)

	if err := os.RemoveAll(dir); err != nil {
		return err
	}

	m.logger.Info("bundle removed",
		"path", dir,
	)

	return nil
}

func (m *Manager) explodeBundles(paths []string) ([]*ExplodedManifest, error) {
	m.logger.Info("exploding bundles")

	manifests := make([]*ExplodedManifest, 0)
	for _, path := range paths {
		manifest, err := m.explodeBundle(path)
		if err != nil {
			return nil, err
		}
		manifests = append(manifests, manifest)
	}

	return manifests, nil
}

func (m *Manager) explodeBundle(path string, opts ...AddOption) (*ExplodedManifest, error) {
	options := NewAddOptions(opts...)

	if err := validateLabels(options.labels); err != nil {
		return nil, err
	}

	m.logger.Info("exploding bundle",
		"path", path,
	)

	var openOpts []OpenOption
	if options.manifestHash != nil {
		openOpts = append(openOpts, WithManifestHash(*options.manifestHash))
	}

	bnd, err := Open(path, openOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to open bundle: %w", err)
	}
	defer bnd.Close()

	if options.validator != nil {
		if err = options.validator(bnd); err != nil {
			return nil, err
		}
	}
	bnd.Rewrite(options.manifestRewriter)

	dir := bnd.ExplodedPath(m.dataDir)
	if err = bnd.WriteExploded(dir); err != nil {
		return nil, fmt.Errorf("failed to explode bundle: %w", err)
	}

	m.logger.Info("bundle exploded",
		"dir", dir,
	)

	return &ExplodedManifest{
		Manifest:        bnd.Manifest,
		ExplodedDataDir: dir,
		Labels:          options.labels,
		Volumes:         options.volumes,
	}, nil
}

func (m *Manager) registerManifests(manifests []*ExplodedManifest) error {
	m.logger.Info("registering manifests")

	// Register detached manifests first to ensure all components
	// are available before a regular manifest is added.
	for _, detached := range []bool{true, false} {
		for _, manifest := range manifests {
			if manifest.IsDetached() != detached {
				continue
			}
			if err := m.registerManifest(manifest); err != nil {
				return err
			}
		}
	}

	return nil
}

func (m *Manager) registerManifest(manifest *ExplodedManifest) error {
	m.logger.Info("registering manifest",
		"name", manifest.Name,
		"hash", manifest.Hash(),
	)

	if manifest.Volumes == nil {
		// No volumes have been configured, attach default volumes.
		err := m.attachDefaultVolumes(manifest)
		if err != nil {
			return err
		}
	}

	if err := manifest.ValidateVolumes(); err != nil {
		return fmt.Errorf("failed to validate volumes: %w", err)
	}

	return m.store.AddManifest(manifest)
}

func (m *Manager) attachDefaultVolumes(manifest *ExplodedManifest) error {
	manifest.Volumes = make(map[string]*volume.Volume)

	for _, comp := range manifest.Components {
		compID, _ := comp.ID().MarshalText()

		for _, volName := range comp.RequiredVolumeNames() {
			volume, err := m.volumeManager.GetOrCreate(map[string]string{
				volume.LabelAutoGenerated: "true",
				volume.LabelRuntimeID:     manifest.ID.String(),
				volume.LabelComponentID:   string(compID),
				volume.LabelName:          volName,
			})
			if err != nil {
				return fmt.Errorf("failed to attach volume: %w", err)
			}

			manifest.Volumes[volName] = volume
		}
	}

	return nil
}

func (m *Manager) openTemporaryBundleRoot(tmpPath string) (string, *os.Root, error) {
	tmpBundleRoot, err := os.OpenRoot(m.tmpBundleDir)
	if err != nil {
		return "", nil, err
	}
	defer tmpBundleRoot.Close()

	dirName := filepath.Dir(tmpPath)
	tmpName := filepath.Base(tmpPath)

	_ = tmpBundleRoot.Mkdir(dirName, 0o700)
	tmpOriginRoot, err := tmpBundleRoot.OpenRoot(dirName)
	if err != nil {
		return "", nil, err
	}
	return tmpName, tmpOriginRoot, nil
}

func validateAndNormalizeURL(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL '%s': %w", rawURL, err)
	}
	return parsedURL.String(), nil
}

func validateAndNormalizeURLs(rawURLs []string) ([]string, error) {
	var normalizedURLs []string

	for _, rawURL := range rawURLs {
		normalizedURL, err := validateAndNormalizeURL(rawURL)
		if err != nil {
			return nil, err
		}
		normalizedURLs = append(normalizedURLs, normalizedURL)
	}

	return normalizedURLs, nil
}

func validateLabels(labels map[string]string) error {
	if len(labels) > maxLabelCount {
		return fmt.Errorf("too many labels")
	}
	for key, value := range labels {
		if len(key) > maxLabelSize || len(value) > maxLabelSize {
			return fmt.Errorf("label too large")
		}
	}
	return nil
}
