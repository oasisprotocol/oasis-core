package seed

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	cmtconfig "github.com/cometbft/cometbft/config"
	cmtp2p "github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/p2p/pex"
	cmtversion "github.com/cometbft/cometbft/version"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	tmcommon "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/common"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/crypto"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	cmflags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

const (
	// This should ideally be dynamically configured internally by CometBFT:
	// https://github.com/tendermint/tendermint/issues/3523
	// This is set to the same value as in CometBFT.
	cometbftSeedDisconnectWaitPeriod = 28 * time.Hour
)

// Service is the seed node service.
type Service struct {
	identity *identity.Identity

	doc *genesis.Document

	addr      *cmtp2p.NetAddress
	transport *cmtp2p.MultiplexTransport
	addrBook  pex.AddrBook
	p2pSwitch *cmtp2p.Switch

	stopOnce sync.Once
	quitCh   chan struct{}
}

// Name implements service.BackgroundService.
func (s *Service) Name() string {
	return "cometbft/seed"
}

// Start implements service.BackgroundService.
func (s *Service) Start() error {
	if err := s.transport.Listen(*s.addr); err != nil {
		return fmt.Errorf("cometbft/seed: failed to listen on transport: %w", err)
	}

	// Start switch.
	if err := s.p2pSwitch.Start(); err != nil {
		return fmt.Errorf("cometbft/seed: failed to start P2P switch: %w", err)
	}

	return nil
}

// Stop implements service.BackgroundService.
func (s *Service) Stop() {
	s.stopOnce.Do(func() {
		close(s.quitCh)
		// Save the address book.
		if s.addrBook != nil {
			s.addrBook.Save()
		}

		// Stop the switch.
		if s.p2pSwitch != nil {
			_ = s.p2pSwitch.Stop()
			s.p2pSwitch.Wait()
		}
	})
}

// Quit implements service.BackgroundService.
func (s *Service) Quit() <-chan struct{} {
	return s.quitCh
}

// Cleanup implements service.BackgroundService.
func (s *Service) Cleanup() {
	// No cleanup in particular.
}

// GetChainContext returns chain context from which network/chain ID was derived.
func (s *Service) GetChainContext() string {
	return s.doc.ChainContext()
}

// GetPeers returns a list of peers that are connected to the seed.
func (s *Service) GetPeers() []string {
	tmpeers := s.p2pSwitch.Peers().List()
	peers := make([]string, 0, len(tmpeers))
	for _, tmpeer := range tmpeers {
		p := string(tmpeer.ID()) + "@" + tmpeer.RemoteAddr().String()
		peers = append(peers, p)
	}
	return peers
}

// GetAddresses returns a list of configured external addresses.
func (s *Service) GetAddresses() ([]node.ConsensusAddress, error) {
	u, err := tmcommon.GetExternalAddress()
	if err != nil {
		return nil, err
	}

	var addr node.ConsensusAddress
	if err = addr.Address.UnmarshalText([]byte(u.Host)); err != nil {
		return nil, fmt.Errorf("cometbft: failed to parse external address host: %w", err)
	}
	addr.ID = s.identity.P2PSigner.Public()

	return []node.ConsensusAddress{addr}, nil
}

// New creates a new seed node service.
func New(dataDir string, identity *identity.Identity, genesisProvider genesis.Provider) (*Service, error) {
	var err error

	// This is heavily inspired by https://gitlab.com/polychainlabs/tenderseed
	// and reaches into CometBFT to spin up the minimum components required
	// to get the PEX reactor to operate in seed mode.

	srv := &Service{
		quitCh:   make(chan struct{}),
		identity: identity,
	}

	seedDataDir := filepath.Join(dataDir, "cometbft-seed")
	if err = tmcommon.InitDataDir(seedDataDir); err != nil {
		return nil, fmt.Errorf("cometbft/seed: failed to initialize data dir: %w", err)
	}

	tmSeeds, err := tmcommon.ConsensusAddressesToCometBFT(config.GlobalConfig.P2P.Seeds)
	if err != nil {
		return nil, fmt.Errorf("cometbft/seed: failed to convert seed addresses: %w", err)
	}

	p2pCfg := cmtconfig.DefaultP2PConfig()
	p2pCfg.SeedMode = true
	p2pCfg.Seeds = strings.Join(tmSeeds, ",")
	p2pCfg.ExternalAddress = config.GlobalConfig.Consensus.ExternalAddress
	p2pCfg.MaxNumInboundPeers = config.GlobalConfig.Consensus.P2P.MaxNumInboundPeers
	p2pCfg.MaxNumOutboundPeers = config.GlobalConfig.Consensus.P2P.MaxNumOutboundPeers
	p2pCfg.SendRate = config.GlobalConfig.Consensus.P2P.SendRate
	p2pCfg.RecvRate = config.GlobalConfig.Consensus.P2P.RecvRate
	p2pCfg.AddrBookStrict = !(config.GlobalConfig.Consensus.Debug.P2PAddrBookLenient && cmflags.DebugDontBlameOasis())
	p2pCfg.AllowDuplicateIP = config.GlobalConfig.Consensus.Debug.P2PAllowDuplicateIP && cmflags.DebugDontBlameOasis()

	nodeKey := &cmtp2p.NodeKey{PrivKey: crypto.SignerToCometBFT(identity.P2PSigner)}

	doc, err := genesisProvider.GetGenesisDocument()
	if err != nil {
		return nil, fmt.Errorf("cometbft/seed: failed to get genesis document: %w", err)
	}
	srv.doc = doc

	nodeInfo := cmtp2p.DefaultNodeInfo{
		ProtocolVersion: cmtp2p.NewProtocolVersion(
			cmtversion.P2PProtocol,
			cmtversion.BlockProtocol,
			version.CometBFTAppVersion,
		),
		DefaultNodeID: nodeKey.ID(),
		ListenAddr:    config.GlobalConfig.Consensus.ListenAddress,
		Network:       api.CometBFTChainID(doc.ChainContext()),
		Version:       cmtversion.TMCoreSemVer,
		Channels:      []byte{pex.PexChannel},
		Moniker:       "oasis-seed-" + identity.P2PSigner.Public().String(),
	}

	// Carve out all of the services.
	logger := tmcommon.NewLogAdapter(!config.GlobalConfig.Consensus.LogDebug)
	if srv.addr, err = cmtp2p.NewNetAddressString(cmtp2p.IDAddressString(nodeInfo.DefaultNodeID, nodeInfo.ListenAddr)); err != nil {
		return nil, fmt.Errorf("cometbft/seed: failed to create seed address: %w", err)
	}
	srv.transport = cmtp2p.NewMultiplexTransport(nodeInfo, *nodeKey, cmtp2p.MConnConfig(p2pCfg))

	addrBookPath := filepath.Join(seedDataDir, tmcommon.ConfigDir, "addrbook.json")
	srv.addrBook = pex.NewAddrBook(addrBookPath, p2pCfg.AddrBookStrict)
	srv.addrBook.SetLogger(logger.With("module", "book"))
	if err = srv.addrBook.Start(); err != nil {
		return nil, fmt.Errorf("cometbft/seed: failed to start address book: %w", err)
	}

	if !(config.GlobalConfig.Consensus.Debug.DisableAddrBookFromGenesis && cmflags.DebugDontBlameOasis()) {
		if err = populateAddrBookFromGenesis(srv.addrBook, doc, srv.addr); err != nil {
			return nil, fmt.Errorf("cometbft/seed: failed to populate address book from genesis: %w", err)
		}
	}

	// Use p2pCfg.Seeds since there the IDs are already lowercased.
	// Use FieldsFunc so that empty string is handled correctly.
	seeds := strings.FieldsFunc(
		p2pCfg.Seeds,
		func(c rune) bool {
			return c == ','
		},
	)
	pexReactor := pex.NewReactor(srv.addrBook, &pex.ReactorConfig{
		SeedMode:                 p2pCfg.SeedMode,
		Seeds:                    seeds,
		SeedDisconnectWaitPeriod: cometbftSeedDisconnectWaitPeriod,
	})
	pexReactor.SetLogger(logger.With("module", "pex"))

	srv.p2pSwitch = cmtp2p.NewSwitch(p2pCfg, srv.transport)
	srv.p2pSwitch.SetLogger(logger.With("module", "switch"))
	srv.p2pSwitch.SetNodeKey(nodeKey)
	srv.p2pSwitch.SetAddrBook(srv.addrBook)
	srv.p2pSwitch.AddReactor("pex", pexReactor)
	srv.p2pSwitch.SetNodeInfo(nodeInfo)

	return srv, nil
}

func populateAddrBookFromGenesis(addrBook cmtp2p.AddrBook, doc *genesis.Document, ourAddr *cmtp2p.NetAddress) error {
	logger := logging.GetLogger("consensus/cometbft/seed")

	// Convert to a representation suitable for address book population.
	var addrs []*cmtp2p.NetAddress
	for _, v := range doc.Registry.Nodes {
		var openedNode node.Node
		if err := v.Open(registry.RegisterGenesisNodeSignatureContext, &openedNode); err != nil {
			return fmt.Errorf("cometbft/seed: failed to verify validator: %w", err)
		}
		// TODO: This should cross check that the entity is valid.
		if !openedNode.HasRoles(node.RoleValidator) {
			continue
		}

		var tmvAddr *cmtp2p.NetAddress
		tmvAddr, err := api.NodeToP2PAddr(&openedNode)
		if err != nil {
			logger.Error("failed to reformat genesis validator address",
				"err", err,
			)
			continue
		}

		addrs = append(addrs, tmvAddr)
	}

	// Populate the address book with the genesis validators.
	addrBook.AddOurAddress(ourAddr) // Required or AddrBook.AddAddress will fail.
	for _, v := range addrs {
		// Remove the address first as otherwise CometBFT's address book
		// may not actually add the new address.
		addrBook.RemoveAddress(v)

		if err := addrBook.AddAddress(v, ourAddr); err != nil {
			logger.Error("failed to add genesis validator to address book",
				"err", err,
			)
		}
	}

	return nil
}
