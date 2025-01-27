package peerstore

import (
	"container/list"
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/scheduling"
	"github.com/oasisprotocol/oasis-core/go/p2p/backup"
)

const (
	// PeerRegistrationTTL is a deadline for the next registration.
	PeerRegistrationTTL = time.Hour

	// backupTaskName is the name of the task responsible for periodical backups.
	backupTaskName = "peerstore-backup"

	// backupDelay is the initial time delay for backups.
	backupDelay = 15 * time.Minute

	// backupInterval is the time interval between backups.
	backupInterval = 15 * time.Minute

	// cleanupTaskName is the name of the task responsible for periodical cleanups.
	cleanupTaskName = "peerstore-cleanup"

	// cleanupInterval is the interval for periodic store cleanup.
	cleanupInterval = time.Minute

	// defaultMaxPeers is the default maximum number of peers the store will hold before starting
	// to reject new registration requests.
	defaultMaxPeers = 10_000

	// defaultMaxNamespacePeers is the default maximum number of peers the store will register
	// for a namespace before starting to reject new registration requests for the namespace.
	defaultMaxNamespacePeers = 1_000

	// defaultMaxPeerNamespaces is the default maximum number of namespaces a peer can be
	// registered for.
	defaultMaxPeerNamespaces = 20
)

// StoreOptions are store options.
type StoreOptions struct {
	maxPeers   int
	maxNsPeers int
	maxPeerNs  int
}

// StoreOption is a store option setter.
type StoreOption func(opts *StoreOptions)

// WithMaxPeers configures maximum number of peers.
func WithMaxPeers(n int) StoreOption {
	return func(opts *StoreOptions) {
		opts.maxPeers = n
	}
}

// WithMaxNamespacePeers configures maximum number of peers in a namespace.
func WithMaxNamespacePeers(n int) StoreOption {
	return func(opts *StoreOptions) {
		opts.maxNsPeers = n
	}
}

// WithMaxPeerNamespaces configures maximum number of peer's namespaces.
func WithMaxPeerNamespaces(n int) StoreOption {
	return func(opts *StoreOptions) {
		opts.maxPeerNs = n
	}
}

// DefaultStoreOptions returns the default store options.
func DefaultStoreOptions() *StoreOptions {
	return &StoreOptions{
		maxPeers:   defaultMaxPeers,
		maxNsPeers: defaultMaxNamespacePeers,
		maxPeerNs:  defaultMaxPeerNamespaces,
	}
}

type registration struct {
	ns      string
	info    peer.AddrInfo
	expires time.Time

	expirationPos *list.Element
}

// Store is an in-memory data structure for storing peers' data.
type Store struct {
	logger *logging.Logger

	maxPeers   int
	maxNsPeers int
	maxPeerNs  int

	mu             sync.RWMutex
	peerNamespaces map[peer.ID]map[string]struct{}
	registrations  map[string]map[peer.ID]*registration
	expirations    *list.List

	backup           backup.Backend
	backupScheduler  scheduling.Scheduler
	cleanupScheduler scheduling.Scheduler
}

// NewStore creates a new peer store.
func NewStore(b backup.Backend, opts ...StoreOption) *Store {
	so := DefaultStoreOptions()
	for _, opt := range opts {
		opt(so)
	}

	l := logging.GetLogger("p2p/discovery/peerstore")

	store := Store{
		logger:         l,
		backup:         b,
		maxPeers:       so.maxPeers,
		maxNsPeers:     so.maxNsPeers,
		maxPeerNs:      so.maxPeerNs,
		peerNamespaces: make(map[peer.ID]map[string]struct{}),
		registrations:  make(map[string]map[peer.ID]*registration),
		expirations:    list.New(),
	}

	store.backupScheduler = scheduling.NewFixedRateScheduler(backupDelay, backupInterval)
	store.backupScheduler.AddTask(backupTaskName, store.Backup)

	store.cleanupScheduler = scheduling.NewFixedRateScheduler(0, cleanupInterval)
	store.cleanupScheduler.AddTask(cleanupTaskName, store.cleanup)

	return &store
}

// Add inserts the given peer address into the store under the given namespace.
func (s *Store) Add(ns string, info peer.AddrInfo) (time.Duration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	nsPeers, ok := s.registrations[ns]
	if !ok {
		nsPeers = make(map[peer.ID]*registration)
		s.registrations[ns] = nsPeers
	}

	// Extend/update registration.
	reg, ok := nsPeers[info.ID]
	if ok {
		reg.info = info
		reg.expires = time.Now().Add(PeerRegistrationTTL)
		s.expirations.MoveToBack(reg.expirationPos)

		return PeerRegistrationTTL, nil
	}

	// Or add a new one.
	if len(s.peerNamespaces) >= s.maxPeers {
		return 0, fmt.Errorf("too many peers")
	}

	if len(nsPeers) >= s.maxNsPeers {
		return 0, fmt.Errorf("too many peers registered for the namespace")
	}

	peerNs, ok := s.peerNamespaces[info.ID]
	if !ok {
		peerNs = make(map[string]struct{})
		s.peerNamespaces[info.ID] = peerNs
	}
	if len(peerNs) >= s.maxPeerNs {
		return 0, fmt.Errorf("peer registered too many namespaces")
	}

	reg = &registration{
		ns:      ns,
		info:    info,
		expires: time.Now().Add(PeerRegistrationTTL),
	}
	reg.expirationPos = s.expirations.PushBack(reg)

	nsPeers[info.ID] = reg
	peerNs[ns] = struct{}{}

	return PeerRegistrationTTL, nil
}

// Remove removes the peer from the given namespace.
func (s *Store) Remove(ns string, pid peer.ID) {
	s.mu.Lock()
	defer s.mu.Unlock()

	peers, ok := s.registrations[ns]
	if !ok {
		return
	}

	reg, ok := peers[pid]
	if !ok {
		return
	}

	delete(peers, pid)

	if len(s.registrations[ns]) == 0 {
		delete(s.registrations, ns)
	}
	s.expirations.Remove(reg.expirationPos)

	delete(s.peerNamespaces[pid], ns)
	if len(s.peerNamespaces[pid]) == 0 {
		delete(s.peerNamespaces, pid)
	}
}

// NamespacePeers returns a random selection of peers from the given namespace.
func (s *Store) NamespacePeers(ns string, limit int) []peer.AddrInfo {
	if limit <= 0 {
		return []peer.AddrInfo{}
	}

	now := time.Now()

	peers := func() []peer.AddrInfo {
		s.mu.RLock()
		defer s.mu.RUnlock()

		peerMap, ok := s.registrations[ns]
		if !ok {
			return []peer.AddrInfo{}
		}

		// A more advanced store should optimize this.
		peers := make([]peer.AddrInfo, 0, len(peerMap))
		for _, reg := range peerMap {
			if reg.expires.Before(now) {
				continue
			}
			peers = append(peers, reg.info)
		}

		return peers
	}()

	if limit > len(peers) {
		return peers
	}

	// Shuffle only first few peers.
	for i := 0; i < limit; i++ {
		j := i + rand.Intn(len(peers)-i)
		peers[i], peers[j] = peers[j], peers[i]
	}

	return peers[:limit]
}

// Peers returns peers from all namespaces without duplicates.
func (s *Store) Peers() []peer.AddrInfo {
	now := time.Now()

	peerMap := make(map[peer.ID]peer.AddrInfo)
	func() {
		s.mu.RLock()
		defer s.mu.RUnlock()

		for _, regs := range s.registrations {
			for _, reg := range regs {
				if reg.expires.Before(now) {
					continue
				}
				peerMap[reg.info.ID] = reg.info
			}
		}
	}()

	peers := make([]peer.AddrInfo, 0, len(peerMap))
	for _, peer := range peerMap {
		peers = append(peers, peer)
	}

	return peers
}

// Restore loads peers from the backup.
func (s *Store) Restore(ctx context.Context) error {
	nsPeers, err := s.backup.Restore(ctx)
	if err != nil {
		s.logger.Error("failed to restore peers from the backup",
			"err", err,
		)
		return err
	}

	for ns, peers := range nsPeers {
		for _, peer := range peers {
			_, err = s.Add(ns, peer)
			if err != nil {
				s.logger.Error("failed to add peer to the store",
					"err", err,
				)
				return err
			}
		}
	}

	return nil
}

// Backup persists peers to the backup.
func (s *Store) Backup(ctx context.Context) error {
	nsPeers := make(map[string][]peer.AddrInfo)

	func() {
		s.mu.RLock()
		defer s.mu.RUnlock()

		for ns, regs := range s.registrations {
			peers := make([]peer.AddrInfo, 0, len(regs))
			for _, reg := range regs {
				peers = append(peers, reg.info)
			}
			nsPeers[ns] = peers
		}
	}()

	return s.backup.Backup(ctx, nsPeers)
}

// Start starts background services which periodically backup and clean the store.
func (s *Store) Start() {
	s.backupScheduler.Start()
	s.cleanupScheduler.Start()
}

// Stop stops all background services. This method blocks until all services are stopped.
func (s *Store) Stop() {
	s.backupScheduler.Stop()
	s.cleanupScheduler.Stop()
}

// cleanup removes peers which registration expired.
func (s *Store) cleanup(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for e := s.expirations.Front(); e != nil; {
		reg, ok := e.Value.(*registration)
		if !ok {
			panic("failed to cast registration")
		}
		if reg.expires.After(time.Now()) {
			break
		}

		next := e.Next()
		s.expirations.Remove(e)
		e = next

		delete(s.registrations[reg.ns], reg.info.ID)
		if len(s.registrations[reg.ns]) == 0 {
			delete(s.registrations, reg.ns)
		}
	}

	return nil
}

// total returns the number of peers in all namespaces counting duplicates twice.
func (s *Store) total() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := 0
	for _, ns := range s.registrations {
		total += len(ns)
	}

	return total
}

// size returns the number of peers in the given namespace.
func (s *Store) size(ns string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.registrations[ns])
}
