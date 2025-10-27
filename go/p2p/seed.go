package p2p

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/p2p/api"
	"github.com/oasisprotocol/oasis-core/go/p2p/backup"
	"github.com/oasisprotocol/oasis-core/go/p2p/discovery/bootstrap"
	"github.com/oasisprotocol/oasis-core/go/p2p/discovery/peerstore"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
)

const (
	// peerstoreBucketName is the name of the bucket in which peers from the peerstore are stored.
	peerstoreBucketName = "p2p/seed/peerstore"

	// peerstoreBucketKey is the bucket key under which peers from the peerstore are stored.
	peerstoreBucketKey = "peers"
)

// seedNode is a P2P seed node which serves information about other peers in the network.
type seedNode struct {
	logger *logging.Logger

	host  host.Host
	store *peerstore.Store

	bootSrv rpc.Server

	quitCh chan struct{}
}

// NewSeedNode creates a new P2P seed node service.
func NewSeedNode(cfg *SeedConfig) (api.SeedService, error) {
	logger := logging.GetLogger("p2p/seed")

	host, _, err := NewHost(&cfg.HostConfig)
	if err != nil {
		return nil, err
	}

	backup := backup.NewCommonStoreBackend(cfg.CommonStore, peerstoreBucketName, peerstoreBucketKey)
	store := peerstore.NewStore(backup)

	var bootSrv rpc.Server
	if cfg.BootstrapDiscoveryConfig.Enable {
		bootSrv = bootstrap.NewServer(store)
	}

	return &seedNode{
		logger:  logger,
		host:    host,
		store:   store,
		bootSrv: bootSrv,
		quitCh:  make(chan struct{}),
	}, nil
}

// Cleanup implements service.BackgroundService.
func (s *seedNode) Cleanup() {
}

// Name implements service.BackgroundService.
func (s *seedNode) Name() string {
	return "libp2p/seed"
}

// Start implements service.BackgroundService.
func (s *seedNode) Start() error {
	if err := s.store.Restore(context.TODO()); err != nil {
		s.logger.Debug("failed to restore peer store",
			"err", err,
		)
	}
	s.store.Start()

	if s.bootSrv != nil {
		s.registerProtocolServer(s.bootSrv)
	}

	return nil
}

// Stop implements service.BackgroundService.
func (s *seedNode) Stop() {
	defer close(s.quitCh)

	// Some blocking services can be stopped concurrently.
	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Go(func() {
		if err := s.host.Close(); err != nil {
			s.logger.Debug("failed to stop host",
				"err", err,
			)
		}
	})

	s.store.Stop()
}

// Quit implements service.BackgroundService.
func (s *seedNode) Quit() <-chan struct{} {
	return s.quitCh
}

// Peers implements api.SeedService.
func (s *seedNode) Peers() []string {
	peers := s.store.Peers()
	encoded := make([]string, 0, len(peers))
	for _, info := range peers {
		encoded = append(encoded, api.AddrInfoToString(info)...)
	}
	sort.Strings(encoded)
	return encoded
}

// Addresses implements api.SeedService.
func (s *seedNode) Addresses() []string {
	info := peer.AddrInfo{
		ID:    s.host.ID(),
		Addrs: s.host.Addrs(),
	}

	return []string{info.String()}
}

func (s *seedNode) registerProtocolServer(srv rpc.Server) {
	s.host.SetStreamHandler(srv.Protocol(), srv.HandleStream)

	s.logger.Info("registered protocol server",
		"protocol_id", srv.Protocol(),
	)
}

// SeedConfig describes a set of settings for a seed.
type SeedConfig struct {
	CommonStore *persistent.CommonStore

	HostConfig
	BootstrapDiscoveryConfig
}

// NewSeed creates a new P2P seed node service.
func (cfg *SeedConfig) NewSeed() (api.SeedService, error) {
	return NewSeedNode(cfg)
}

// Load loads seed configuration.
func (cfg *SeedConfig) Load() error {
	var hostCfg HostConfig
	if err := hostCfg.Load(); err != nil {
		return fmt.Errorf("failed to load host config: %w", err)
	}

	var bootstrapCfg BootstrapDiscoveryConfig
	if err := bootstrapCfg.Load(); err != nil {
		return fmt.Errorf("failed to load bootstrap config: %w", err)
	}

	cfg.HostConfig = hostCfg
	cfg.BootstrapDiscoveryConfig = bootstrapCfg

	return nil
}
