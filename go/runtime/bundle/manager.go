package bundle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	cmSync "github.com/oasisprotocol/oasis-core/go/common/sync"
	"github.com/oasisprotocol/oasis-core/go/config"
)

const (
	// discoveryInterval is the time interval between (failed) bundle discoveries.
	discoveryInterval = 15 * time.Minute

	// requestTimeout is the time limit for http client requests.
	requestTimeout = time.Minute

	// maxMetadataSizeBytes is the maximum allowed metadata size in bytes.
	maxMetadataSizeBytes = 2 * 1024 // 2 KB

	// maxDefaultBundleSizeBytes is the maximum allowed default bundle size
	// in bytes.
	maxDefaultBundleSizeBytes = 20 * 1024 * 1024 // 20 MB
)

// ManifestStore is an interface that defines methods for storing manifests.
type ManifestStore interface {
	// HasManifest returns true iff the store already contains a manifest
	// with the given hash.
	HasManifest(hash hash.Hash) bool

	// AddManifest adds the provided manifest, whose components were extracted
	// to the specified directory, to the store.
	AddManifest(manifest *Manifest, dir string) error
}

// Manager is responsible for managing bundles.
type Manager struct {
	mu sync.RWMutex

	startOne   cmSync.One
	discoverCh chan struct{}

	dataDir        string
	bundleDir      string
	manifestHashes map[common.Namespace][]hash.Hash

	globalBaseURLs  []string
	runtimeBaseURLs map[common.Namespace][]string
	client          *http.Client

	maxBundleSizeBytes int64

	store ManifestStore

	logger logging.Logger
}

// NewManager creates a new bundle manager.
func NewManager(dataDir string, store ManifestStore) *Manager {
	logger := logging.GetLogger("runtime/bundle/manager")

	client := http.Client{
		Timeout: requestTimeout,
	}

	bundleSize := int64(maxDefaultBundleSizeBytes)
	if size := config.GlobalConfig.Runtime.MaxBundleSize; size != "" {
		bundleSize = int64(config.ParseSizeInBytes(size))
	}

	return &Manager{
		startOne:           cmSync.NewOne(),
		discoverCh:         make(chan struct{}, 1),
		dataDir:            dataDir,
		bundleDir:          ExplodedPath(dataDir),
		manifestHashes:     make(map[common.Namespace][]hash.Hash),
		client:             &client,
		maxBundleSizeBytes: bundleSize,
		store:              store,
		logger:             *logger,
	}
}

// Init sets up bundle manager using node configuration and adds configured
// and cached bundles (that are guaranteed to be exploded) to the store.
func (m *Manager) Init() error {
	// Consolidate all bundles in one place, which could be useful
	// if we implement P2P sharing in the future.
	if err := m.copyBundles(); err != nil {
		return err
	}

	// Add copied and cached bundles (that are guaranteed to be exploded)
	// to the store.
	if err := m.Discover(); err != nil {
		return err
	}

	// Validate global registry URLs.
	globalBaseURLs, err := validateAndNormalizeURLs(config.GlobalConfig.Runtime.Registries)
	if err != nil {
		return err
	}

	// Validate each runtime's registry URLs.
	runtimeBaseURLs := make(map[common.Namespace][]string)

	for _, runtime := range config.GlobalConfig.Runtime.Runtimes {
		urls, err := validateAndNormalizeURLs(runtime.Registries)
		if err != nil {
			return err
		}
		if len(urls) == 0 {
			continue
		}
		runtimeBaseURLs[runtime.ID] = urls
	}

	// Update manager.
	m.mu.Lock()
	defer m.mu.Unlock()

	m.globalBaseURLs = globalBaseURLs
	m.runtimeBaseURLs = runtimeBaseURLs

	return nil
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
	m.logger.Info("starting",
		"dir", m.bundleDir,
	)

	ticker := time.NewTicker(discoveryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
		case <-m.discoverCh:
		case <-ctx.Done():
			m.logger.Info("stopping")
			return
		}

		_ = m.Discover()
		m.Download()
	}
}

// Discover searches for new bundles in the bundle directory and adds them
// to the store.
func (m *Manager) Discover() error {
	m.logger.Debug("discovering bundles")

	entries, err := os.ReadDir(m.bundleDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		m.logger.Error("failed to read bundle directory",
			"err", err,
			"dir", m.bundleDir,
		)
		return fmt.Errorf("failed to read bundle directory: %w", err)
	}

	for _, entry := range entries {
		filename := entry.Name()
		if entry.IsDir() || filepath.Ext(filename) != FileExtension {
			continue
		}

		baseFilename := strings.TrimSuffix(filename, FileExtension)
		if len(baseFilename) != 2*hash.Size {
			continue
		}

		var manifestHash hash.Hash
		if err = manifestHash.UnmarshalHex(baseFilename); err != nil {
			continue
		}

		if m.store.HasManifest(manifestHash) {
			continue
		}

		m.logger.Info("found new bundle",
			"file", filename,
		)

		src := filepath.Join(m.bundleDir, filename)
		manifest, dir, err := m.explodeBundle(src, WithManifestHash(manifestHash))
		if err != nil {
			m.logger.Error("failed to explode bundle",
				"err", err,
				"src", src,
			)
			return err
		}

		if err = m.store.AddManifest(manifest, dir); err != nil {
			m.logger.Error("failed to add manifest to store",
				"err", err,
			)
			return fmt.Errorf("failed to add manifest to store: %w", err)
		}
	}

	return nil
}

// Queue updates the checksums of bundles that need to be downloaded
// for the given runtime.
func (m *Manager) Queue(runtimeID common.Namespace, manifestHashes []hash.Hash) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Download bundles only if at least one endpoint is configured.
	if len(m.globalBaseURLs) == 0 && len(m.runtimeBaseURLs[runtimeID]) == 0 {
		return
	}

	// Filter out bundles that have already been fetched.
	var hashes []hash.Hash
	for _, hash := range manifestHashes {
		if m.store.HasManifest(hash) {
			continue
		}
		hashes = append(hashes, hash)
	}

	// Update the queue with the new hashes.
	if len(hashes) == 0 {
		delete(m.manifestHashes, runtimeID)
		return
	}
	m.manifestHashes[runtimeID] = hashes

	// Trigger immediate discovery or download of new bundles.
	select {
	case m.discoverCh <- struct{}{}:
	default:
	}
}

// Download tries to download bundles in the queue.
func (m *Manager) Download() {
	m.mu.RLock()
	runtimeIDs := slices.Collect(maps.Keys(m.manifestHashes))
	m.mu.RUnlock()

	for _, runtimeID := range runtimeIDs {
		m.downloadBundles(runtimeID)
	}
}

func (m *Manager) downloadBundles(runtimeID common.Namespace) {
	// Try to download queued bundles.
	m.mu.RLock()
	hashes := m.manifestHashes[runtimeID]
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
	for _, hash := range m.manifestHashes[runtimeID] {
		if _, ok := downloaded[hash]; ok {
			continue
		}
		pending = append(pending, hash)
	}
	if len(pending) == 0 {
		delete(m.manifestHashes, runtimeID)
		return
	}
	m.manifestHashes[runtimeID] = pending
}

func (m *Manager) downloadBundle(runtimeID common.Namespace, manifestHash hash.Hash) error {
	var errs error

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

	m.logger.Debug("downloading metadata",
		"url", metaURL,
	)

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

	m.logger.Debug("downloading bundle",
		"url", bundleURL,
	)

	src, err := m.fetchBundle(bundleURL)
	if err != nil {
		m.logger.Error("failed to download bundle",
			"err", err,
			"url", metaURL,
		)
		return fmt.Errorf("failed to download bundle: %w", err)
	}
	defer os.Remove(src)

	m.logger.Info("bundle downloaded",
		"url", bundleURL,
	)

	manifest, dir, err := m.explodeBundle(src, WithManifestHash(manifestHash))
	if err != nil {
		m.logger.Error("failed to explode bundle",
			"err", err,
			"src", src,
		)
		return err
	}

	if err := m.store.AddManifest(manifest, dir); err != nil {
		m.logger.Error("failed to add manifest to store",
			"err", err,
		)
		return fmt.Errorf("failed to add manifest: %w", err)
	}

	filename := fmt.Sprintf("%s%s", manifestHash.Hex(), FileExtension)
	dst := filepath.Join(m.bundleDir, filename)
	if err = os.Rename(src, dst); err != nil {
		m.logger.Error("failed to move bundle",
			"err", err,
			"src", src,
			"dst", dst,
		)
	}

	m.logger.Debug("bundle stored",
		"dst", dst,
	)

	return nil
}

func (m *Manager) fetchMetadata(url string) (string, error) {
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

	return strings.TrimSpace(buffer.String()), nil
}

func (m *Manager) fetchBundle(url string) (string, error) {
	resp, err := m.client.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch bundle: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch bundle: invalid status code %d", resp.StatusCode)
	}

	// Copy to a temporary file. as downloaded bundles are unverified.
	file, err := os.CreateTemp("", fmt.Sprintf("oasis-bundle-*%s", FileExtension))
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer func() {
		file.Close()
		if err != nil {
			_ = os.Remove(file.Name())
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

	return file.Name(), nil
}

func (m *Manager) copyBundles() error {
	if err := common.Mkdir(m.bundleDir); err != nil {
		return err
	}

	for _, path := range config.GlobalConfig.Runtime.Paths {
		if err := m.copyBundle(path); err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) copyBundle(src string) error {
	m.logger.Info("copying bundle",
		"src", src,
	)

	filename, err := func() (string, error) {
		bnd, err := Open(src)
		if err != nil {
			m.logger.Error("failed to open bundle",
				"err", err,
				"src", src,
			)
			return "", fmt.Errorf("failed to open bundle: %w", err)
		}
		defer bnd.Close()

		return bnd.GenerateFilename(), nil
	}()
	if err != nil {
		return err
	}

	dst := filepath.Join(m.bundleDir, filename)
	switch _, err := os.Stat(dst); err {
	case nil:
		m.logger.Info("bundle already exists",
			"src", src,
			"dst", dst,
		)
		return nil
	default:
		if !os.IsNotExist(err) {
			m.logger.Error("failed to stat bundle",
				"err", err,
				"dst", dst,
			)
			return fmt.Errorf("failed to stat bundle %w", err)
		}
	}

	if err := common.CopyFile(src, dst); err != nil {
		m.logger.Error("failed to copy bundle",
			"err", err,
			"src", src,
			"dst", dst,
		)
		return fmt.Errorf("failed to copy bundle: %w", err)
	}

	m.logger.Info("bundle copied",
		"src", src,
		"dst", dst,
	)

	return nil
}

func (m *Manager) explodeBundle(path string, opts ...OpenOption) (*Manifest, string, error) {
	m.logger.Info("exploding bundle",
		"path", path,
	)

	bnd, err := Open(path, opts...)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open bundle: %w", err)
	}
	defer bnd.Close()

	dir, err := bnd.WriteExploded(m.dataDir)
	if err != nil {
		return nil, "", fmt.Errorf("failed to explode bundle: %w", err)
	}

	m.logger.Info("bundle exploded",
		"dir", dir,
	)

	return bnd.Manifest, dir, nil
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
