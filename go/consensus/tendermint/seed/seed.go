package seed

import (
	"fmt"
	"path/filepath"
	"sync"

	"github.com/spf13/viper"
	"github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/p2p/pex"
	"github.com/tendermint/tendermint/types"
	"github.com/tendermint/tendermint/version"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/common"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

var logger = logging.GetLogger("consensus/tendermint/seed")

type seedService struct {
	consensus.BaseBackend

	addr      *p2p.NetAddress
	transport *p2p.MultiplexTransport
	addrBook  pex.AddrBook
	p2pSwitch *p2p.Switch

	stopOnce sync.Once
	quitCh   chan struct{}
}

// Name returns the service name.
func (srv *seedService) Name() string {
	return "tendermint/seed"
}

// Start starts the service.
func (srv *seedService) Start() error {
	if err := srv.transport.Listen(*srv.addr); err != nil {
		return fmt.Errorf("tendermint/seed: failed to listen on transport: %w", err)
	}

	// Start switch.
	if err := srv.p2pSwitch.Start(); err != nil {
		return fmt.Errorf("tendermint/seed: failed to start P2P switch: %w", err)
	}

	return nil
}

// Stop halts the service.
func (srv *seedService) Stop() {
	srv.stopOnce.Do(func() {
		close(srv.quitCh)
		// Save the address book.
		if srv.addrBook != nil {
			srv.addrBook.Save()
		}

		// Stop the switch.
		if srv.p2pSwitch != nil {
			_ = srv.p2pSwitch.Stop()
			srv.p2pSwitch.Wait()
		}
	})
}

// Quit reuturns a channel that will be clsoed when the service terminates.
func (srv *seedService) Quit() <-chan struct{} {
	return srv.quitCh
}

// Cleanup performs the service specific post-termination cleanup.
func (srv *seedService) Cleanup() {
	// No cleanup in particular.
}

// New creates a new seed-only consensus service.
func New(dataDir string, identity *identity.Identity, genesisProvider genesis.Provider) (consensus.Backend, error) {
	var err error

	// This is heavily inspired by https://gitlab.com/polychainlabs/tenderseed
	// and reaches into tendermint to spin up the minimum components requried
	// to get the PEX reactor to operate in seed mode.

	srv := &seedService{
		quitCh: make(chan struct{}),
	}

	seedDataDir := filepath.Join(dataDir, "tendermint-seed")
	if err = common.InitDataDir(seedDataDir); err != nil {
		return nil, fmt.Errorf("tendermint/seed: failed to initialize data dir: %w", err)
	}

	p2pCfg := config.DefaultP2PConfig()
	p2pCfg.AllowDuplicateIP = true
	p2pCfg.SeedMode = true
	p2pCfg.AddrBookStrict = !viper.GetBool(common.CfgDebugP2PAddrBookLenient)
	// MaxNumInboundPeers/MaxNumOutboundPeers

	nodeKey := &p2p.NodeKey{PrivKey: crypto.SignerToTendermint(identity.P2PSigner)}

	doc, err := genesisProvider.GetGenesisDocument()
	if err != nil {
		return nil, fmt.Errorf("tendermint/seed: failed to get genesis document: %w", err)
	}

	nodeInfo := p2p.DefaultNodeInfo{
		ProtocolVersion: p2p.NewProtocolVersion(
			version.P2PProtocol,
			version.BlockProtocol,
			0,
		),
		DefaultNodeID: nodeKey.ID(),
		ListenAddr:    viper.GetString(common.CfgCoreListenAddress),
		Network:       doc.ChainContext()[:types.MaxChainIDLen],
		Version:       "0.0.1",
		Channels:      []byte{pex.PexChannel},
		Moniker:       "oasis-seed-" + identity.P2PSigner.Public().String(),
	}

	// Carve out all of the services.
	logger := common.NewLogAdapter(!viper.GetBool(common.CfgLogDebug))
	if srv.addr, err = p2p.NewNetAddressString(p2p.IDAddressString(nodeInfo.DefaultNodeID, nodeInfo.ListenAddr)); err != nil {
		return nil, fmt.Errorf("tendermint/seed: failed to create seed address: %w", err)
	}
	srv.transport = p2p.NewMultiplexTransport(nodeInfo, *nodeKey, p2p.MConnConfig(p2pCfg))

	addrBookPath := filepath.Join(seedDataDir, common.ConfigDir, "addrbook.json")
	srv.addrBook = pex.NewAddrBook(addrBookPath, p2pCfg.AddrBookStrict)
	srv.addrBook.SetLogger(logger.With("module", "book"))
	if err = srv.addrBook.Start(); err != nil {
		return nil, fmt.Errorf("tendermint/seed: failed to start address book: %w", err)
	}
	if err = populateAddrBookFromGenesis(srv.addrBook, doc, srv.addr); err != nil {
		return nil, fmt.Errorf("tendermint/seed: failed to populate address book from genesis: %w", err)
	}

	pexReactor := pex.NewReactor(srv.addrBook, &pex.ReactorConfig{SeedMode: p2pCfg.SeedMode})
	pexReactor.SetLogger(logger.With("module", "pex"))

	srv.p2pSwitch = p2p.NewSwitch(p2pCfg, srv.transport)
	srv.p2pSwitch.SetLogger(logger.With("module", "switch"))
	srv.p2pSwitch.SetNodeKey(nodeKey)
	srv.p2pSwitch.SetAddrBook(srv.addrBook)
	srv.p2pSwitch.AddReactor("pex", pexReactor)
	srv.p2pSwitch.SetNodeInfo(nodeInfo)

	return srv, nil
}

func populateAddrBookFromGenesis(addrBook p2p.AddrBook, doc *genesis.Document, ourAddr *p2p.NetAddress) error {
	// Convert to a representation suitable for address book population.
	var addrs []*p2p.NetAddress
	for _, v := range doc.Registry.Nodes {
		var openedNode node.Node
		if err := v.Open(registry.RegisterGenesisNodeSignatureContext, &openedNode); err != nil {
			return fmt.Errorf("tendermint/seed: failed to verify validator: %w", err)
		}
		// TODO: This should cross check that the entity is valid.
		if !openedNode.HasRoles(node.RoleValidator) {
			continue
		}

		var tmvAddr *p2p.NetAddress
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
		// Remove the address first as otherwise Tendermint's address book
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
