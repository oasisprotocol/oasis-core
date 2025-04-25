package volume

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	cmSync "github.com/oasisprotocol/oasis-core/go/common/sync"
)

const (
	// descriptorFn is the filename of the descriptor file.
	descriptorFn = "descriptor.json"
	// volumeFn is the filename of the volume file.
	volumeFn = "volume"
)

// Manager is a volume manager.
type Manager struct {
	mu       sync.Mutex
	startOne cmSync.One
	initOnce cmSync.FallibleOnce

	volumesDir string

	volumes map[string]*Volume

	logger *logging.Logger
}

// NewManager creates a new volume manager.
func NewManager(dataDir string) (*Manager, error) {
	logger := logging.GetLogger("runtime/volume/manager")

	return &Manager{
		startOne:   cmSync.NewOne(),
		volumesDir: GetVolumesDir(dataDir),
		volumes:    make(map[string]*Volume),
		logger:     logger,
	}, nil
}

// Start starts the volume manager.
func (m *Manager) Start() {
	m.startOne.TryStart(m.run)
}

// Stop halts the volume manager.
func (m *Manager) Stop() {
	m.startOne.TryStop()
}

func (m *Manager) run(ctx context.Context) {
	m.logger.Info("starting")

	if err := m.ensureInitialized(); err != nil {
		m.logger.Error("failed to initialize volumes",
			"err", err,
		)
		return
	}

	// Start the main task responsible for managing volumes.
	for { //nolint: gosimple
		select {
		case <-ctx.Done():
			m.logger.Info("stopping")
			return
		}

		// TODO: Periodically cleanup unreferenced volumes.
	}
}

func (m *Manager) ensureInitialized() error {
	return m.initOnce.Do(m.loadAndRegisterVolumes)
}

func (m *Manager) loadAndRegisterVolumes() error {
	// Ensure volume directory exists.
	if err := common.Mkdir(m.volumesDir); err != nil {
		m.logger.Error("failed to create volumes directory",
			"err", err,
			"dir", m.volumesDir,
		)
		return err
	}

	// Load all volumes from the volumes directory.
	volumes, err := m.loadVolumes()
	if err != nil {
		m.logger.Error("failed to load volumes",
			"err", err,
		)
		return err
	}

	// Register loaded volumes.
	if err = m.registerVolumes(volumes); err != nil {
		m.logger.Error("failed to register volumes",
			"err", err,
		)
		return err
	}

	m.logger.Info("volumes loaded and registered")

	return nil
}

func (m *Manager) loadVolumes() ([]*Volume, error) {
	m.logger.Info("loading volumes")

	volumes := make([]*Volume, 0)

	entries, err := os.ReadDir(m.volumesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read volumes directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(m.volumesDir, entry.Name())

		b, err := os.ReadFile(filepath.Join(dir, descriptorFn))
		if err != nil {
			m.logger.Warn("skipping unreadable volume descriptor",
				"path", dir,
				"err", err,
			)
			continue
		}

		var dsc Descriptor
		if err = json.Unmarshal(b, &dsc); err != nil {
			m.logger.Warn("skipping malformed volume descriptor",
				"path", dir,
				"err", err,
			)
			continue
		}

		m.logger.Info("volume loaded",
			"id", dsc.ID,
		)

		volumes = append(volumes, &Volume{
			ID:     dsc.ID,
			Path:   filepath.Join(dir, volumeFn),
			Labels: dsc.Labels,
		})
	}

	return volumes, nil
}

func (m *Manager) registerVolumes(volumes []*Volume) error {
	for _, volume := range volumes {
		if err := m.registerVolume(volume); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) registerVolume(volume *Volume) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.registerVolumeLocked(volume)
}

func (m *Manager) registerVolumeLocked(volume *Volume) error {
	if _, ok := m.volumes[volume.ID]; ok {
		return fmt.Errorf("volume '%s' is already registered", volume.ID)
	}

	m.volumes[volume.ID] = volume

	m.logger.Info("volume registered",
		"id", volume.ID,
	)

	return nil
}

// Create creates and registers a new volume.
func (m *Manager) Create(labels map[string]string) (*Volume, error) {
	if err := m.ensureInitialized(); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	return m.createVolumeLocked(labels)
}

func (m *Manager) createVolumeLocked(labels map[string]string) (*Volume, error) {
	volume, err := m.createVolumeDir(labels)
	if err != nil {
		return nil, err
	}

	if err = m.registerVolumeLocked(volume); err != nil {
		return nil, err
	}
	return volume, nil
}

func (m *Manager) createVolumeDir(labels map[string]string) (*Volume, error) {
	// Generate a 256-bit random byte string and use its hex representation as an ID.
	var rawID [32]byte
	if _, err := io.ReadFull(rand.Reader, rawID[:]); err != nil {
		return nil, fmt.Errorf("failed to generate volume identifier: %w", err)
	}

	volumeID := hex.EncodeToString(rawID[:])
	volumeDir := filepath.Join(m.volumesDir, volumeID)
	volume := &Volume{
		ID:     volumeID,
		Path:   filepath.Join(volumeDir, volumeFn),
		Labels: labels,
	}

	// Prepare and write a volume descriptor.
	dsc := &Descriptor{
		ID:     volume.ID,
		Labels: volume.Labels,
	}

	dscFn := filepath.Join(volumeDir, descriptorFn)
	b, err := json.Marshal(dsc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize volume descriptor: %w", err)
	}

	if _, err = os.Lstat(volumeDir); err == nil {
		return nil, fmt.Errorf("volume directory '%s' already exists", volumeDir)
	}
	if err = common.Mkdir(volumeDir); err != nil {
		return nil, fmt.Errorf("failed to create volume directory: %w", err)
	}
	if err = os.WriteFile(dscFn, b, 0o600); err != nil {
		return nil, fmt.Errorf("failed to write volume descriptor: %w", err)
	}

	m.logger.Info("volume created",
		"id", volume.ID,
		"path", volume.Path,
	)

	return volume, nil
}

// Remove removes all volumes with all of the given labels set.
func (m *Manager) Remove(labels map[string]string) error {
	if err := m.ensureInitialized(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, volume := range m.volumes {
		if !volume.HasLabels(labels) {
			continue
		}
		if err := m.removeVolumeLocked(volume); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) removeVolumeLocked(volume *Volume) error {
	volumeDir := filepath.Join(m.volumesDir, volume.ID)
	if err := os.RemoveAll(volumeDir); err != nil {
		return fmt.Errorf("failed to remove volume directory: %w", err)
	}

	delete(m.volumes, volume.ID)
	return nil
}

// Get retrieves the volume with the specified identifier.
//
// If the volume cannot be found, it returns nil
func (m *Manager) Get(id string) (*Volume, bool) {
	if err := m.ensureInitialized(); err != nil {
		return nil, false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	volume, ok := m.volumes[id]
	if !ok {
		return nil, false
	}
	return volume, true
}

// GetOrCreate retrieves the first volume matching given labels or creates a new one.
func (m *Manager) GetOrCreate(labels map[string]string) (*Volume, error) {
	if err := m.ensureInitialized(); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, volume := range m.volumes {
		if !volume.HasLabels(labels) {
			continue
		}
		return volume, nil
	}

	return m.createVolumeLocked(labels)
}

// Volumes returns all volumes with all of the given labels set.
func (m *Manager) Volumes(labels map[string]string) []*Volume {
	if err := m.ensureInitialized(); err != nil {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var volumes []*Volume
	for _, volume := range m.volumes {
		if !volume.HasLabels(labels) {
			continue
		}
		volumes = append(volumes, volume)
	}
	return volumes
}
