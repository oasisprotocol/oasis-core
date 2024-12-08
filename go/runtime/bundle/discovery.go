package bundle

import (
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
	requestTimeout = 10 * time.Second
)

// Discovery is responsible for discovering new bundles.
type Discovery struct {
	mu sync.RWMutex

	startOne   cmSync.One
	discoverCh chan struct{}

	bundleDir      string
	manifestHashes map[common.Namespace][]hash.Hash

	globalBaseURLs  []string
	runtimeBaseURLs map[common.Namespace][]string
	client          *http.Client

	registry Registry

	logger logging.Logger
}

// NewDiscovery creates a new bundle discovery.
func NewDiscovery(dataDir string, registry Registry) *Discovery {
	logger := logging.GetLogger("runtime/bundle/discovery")

	client := http.Client{
		Timeout: requestTimeout,
	}

	return &Discovery{
		startOne:       cmSync.NewOne(),
		discoverCh:     make(chan struct{}, 1),
		bundleDir:      ExplodedPath(dataDir),
		manifestHashes: make(map[common.Namespace][]hash.Hash),
		client:         &client,
		registry:       registry,
		logger:         *logger,
	}
}

// Init sets up bundle discovery using node configuration and adds configured
// and cached bundles to the registry.
func (d *Discovery) Init() error {
	// Consolidate all bundles in one place, which could be useful
	// if we implement P2P sharing in the future.
	if err := d.copyBundles(); err != nil {
		return err
	}

	// Add copied and cached bundles to the registry.
	if err := d.Discover(); err != nil {
		return err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Validate global repository URLs.
	globalBaseURLs, err := validateAndNormalizeURLs(config.GlobalConfig.Runtime.Repositories)
	if err != nil {
		return err
	}

	// Validate each runtime's repository URLs.
	runtimeBaseURLs := make(map[common.Namespace][]string)

	for _, runtime := range config.GlobalConfig.Runtime.Runtimes {
		urls, err := validateAndNormalizeURLs(runtime.Repositories)
		if err != nil {
			return err
		}
		if len(urls) == 0 {
			continue
		}
		runtimeBaseURLs[runtime.ID] = urls
	}

	// Update discovery.
	d.globalBaseURLs = globalBaseURLs
	d.runtimeBaseURLs = runtimeBaseURLs

	return nil
}

// Start starts the bundle discovery.
func (d *Discovery) Start() {
	d.startOne.TryStart(d.run)
}

// Stop halts the bundle discovery.
func (d *Discovery) Stop() {
	d.startOne.TryStop()
}

func (d *Discovery) run(ctx context.Context) {
	d.logger.Info("starting discovery",
		"dir", d.bundleDir,
	)

	ticker := time.NewTicker(discoveryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
		case <-d.discoverCh:
		case <-ctx.Done():
			d.logger.Info("stopping discovery")
			return
		}

		_ = d.Discover()
		d.Download()
	}
}

// Discover searches for new bundles in the bundle directory and adds them
// to the bundle registry.
func (d *Discovery) Discover() error {
	d.logger.Debug("discovering bundles")

	entries, err := os.ReadDir(d.bundleDir)
	if err != nil {
		d.logger.Error("failed to read bundle directory",
			"err", err,
			"dir", d.bundleDir,
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

		if d.registry.HasBundle(manifestHash) {
			continue
		}

		d.logger.Info("found new bundle",
			"file", filename,
		)

		path := filepath.Join(d.bundleDir, filename)
		if err = d.registry.AddBundle(path, manifestHash); err != nil {
			d.logger.Error("failed to add bundle to registry",
				"err", err,
				"path", path,
			)
			return fmt.Errorf("failed to add bundle to registry: %w", err)
		}
	}

	return nil
}

// Queue updates the checksums of bundles that need to be downloaded
// for the given runtime.
func (d *Discovery) Queue(runtimeID common.Namespace, manifestHashes []hash.Hash) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Download bundles only if at least one endpoint is configured.
	if len(d.globalBaseURLs) == 0 && len(d.runtimeBaseURLs[runtimeID]) == 0 {
		return
	}

	// Filter out bundles that have already been fetched.
	var hashes []hash.Hash
	for _, hash := range manifestHashes {
		if d.registry.HasBundle(hash) {
			continue
		}
		hashes = append(hashes, hash)
	}

	// Update the queue with the new hashes.
	if len(hashes) == 0 {
		delete(d.manifestHashes, runtimeID)
		return
	}
	d.manifestHashes[runtimeID] = hashes

	// Trigger immediate discovery or download of new bundles.
	select {
	case d.discoverCh <- struct{}{}:
	default:
	}
}

// Download tries to download bundles in the queue.
func (d *Discovery) Download() {
	d.mu.RLock()
	runtimeIDs := slices.Collect(maps.Keys(d.manifestHashes))
	d.mu.RUnlock()

	for _, runtimeID := range runtimeIDs {
		d.downloadBundles(runtimeID)
	}
}

func (d *Discovery) downloadBundles(runtimeID common.Namespace) {
	// Try to download queued bundles.
	d.mu.RLock()
	hashes := d.manifestHashes[runtimeID]
	d.mu.RUnlock()

	downloaded := make(map[hash.Hash]struct{})
	for _, hash := range hashes {
		if err := d.downloadBundle(runtimeID, hash); err != nil {
			d.logger.Error("failed to download bundle",
				"err", err,
				"runtime_id", runtimeID,
				"manifest_hash", hash.Hex(),
			)
			continue
		}
		downloaded[hash] = struct{}{}
	}

	// Remove downloaded bundles from the queue.
	d.mu.Lock()
	defer d.mu.Unlock()

	var pending []hash.Hash
	for _, hash := range d.manifestHashes[runtimeID] {
		if _, ok := downloaded[hash]; ok {
			continue
		}
		pending = append(pending, hash)
	}
	if len(pending) == 0 {
		delete(d.manifestHashes, runtimeID)
		return
	}
	d.manifestHashes[runtimeID] = pending
}

func (d *Discovery) downloadBundle(runtimeID common.Namespace, manifestHash hash.Hash) error {
	var errs error

	for _, baseURLs := range [][]string{d.runtimeBaseURLs[runtimeID], d.globalBaseURLs} {
		for _, baseURL := range baseURLs {
			if err := d.tryDownloadBundle(runtimeID, manifestHash, baseURL); err != nil {
				errs = errors.Join(errs, err)
				continue
			}

			return nil
		}
	}

	return errs
}

func (d *Discovery) tryDownloadBundle(runtimeID common.Namespace, manifestHash hash.Hash, baseURL string) error {
	filename := fmt.Sprintf("%s%s", manifestHash.Hex(), FileExtension)

	d.logger.Debug("downloading bundle",
		"runtime_id", runtimeID,
		"base_url", baseURL,
		"filename", filename,
	)

	url, err := url.JoinPath(baseURL, filename)
	if err != nil {
		d.logger.Error("failed to construct URL",
			"err", err,
			"base_url", baseURL,
			"filename", filename,
		)
		return fmt.Errorf("failed to construct URL: %w", err)
	}

	src, err := d.fetchBundle(url)
	if err != nil {
		d.logger.Error("failed to download bundle",
			"err", err,
			"url", url,
		)
		return fmt.Errorf("failed to download bundle: %w", err)
	}
	defer os.Remove(src)

	d.logger.Info("bundle downloaded",
		"runtime_id", runtimeID,
		"base_url", baseURL,
		"filename", filename,
	)

	if err := d.registry.AddBundle(src, manifestHash); err != nil {
		d.logger.Error("failed to add bundle to registry",
			"err", err,
		)
		return fmt.Errorf("failed to add bundle: %w", err)
	}

	dst := filepath.Join(d.bundleDir, filename)
	if err = os.Rename(src, dst); err != nil {
		d.logger.Error("failed to move bundle",
			"err", err,
			"src", src,
			"dst", dst,
		)
	}
	return nil
}

func (d *Discovery) fetchBundle(url string) (string, error) {
	resp, err := d.client.Get(url)
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

	if _, err = io.Copy(file, resp.Body); err != nil {
		return "", fmt.Errorf("failed to save bundle: %w", err)
	}

	return file.Name(), nil
}

func (d *Discovery) copyBundles() error {
	if err := common.Mkdir(d.bundleDir); err != nil {
		return err
	}

	for _, path := range config.GlobalConfig.Runtime.Paths {
		if err := d.copyBundle(path); err != nil {
			return err
		}
	}

	return nil
}

func (d *Discovery) copyBundle(src string) error {
	d.logger.Info("copying bundle",
		"src", src,
	)

	filename, err := func() (string, error) {
		bnd, err := Open(src)
		if err != nil {
			d.logger.Error("failed to open bundle",
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

	dst := filepath.Join(d.bundleDir, filename)
	switch _, err := os.Stat(dst); err {
	case nil:
		d.logger.Info("bundle already exists",
			"src", src,
			"dst", dst,
		)
		return nil
	default:
		if !os.IsNotExist(err) {
			d.logger.Error("failed to stat bundle",
				"err", err,
				"dst", dst,
			)
			return fmt.Errorf("failed to stat bundle %w", err)
		}
	}

	if err := common.CopyFile(src, dst); err != nil {
		d.logger.Error("failed to copy bundle",
			"err", err,
			"src", src,
			"dst", dst,
		)
		return fmt.Errorf("failed to open bundle: %w", err)
	}

	d.logger.Info("bundle copied",
		"src", src,
		"dst", dst,
	)

	return nil
}

func validateAndNormalizeURLs(rawURLs []string) ([]string, error) {
	var normalizedURLs []string

	for _, rawURL := range rawURLs {
		parsedURL, err := url.Parse(rawURL)
		if err != nil {
			return nil, fmt.Errorf("invalid URL '%s': %w", rawURL, err)
		}
		normalizedURLs = append(normalizedURLs, parsedURL.String())
	}

	return normalizedURLs, nil
}
