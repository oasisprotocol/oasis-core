package seed

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/tendermint/tendermint/config"
	tmnode "github.com/tendermint/tendermint/node"
	tmtypes "github.com/tendermint/tendermint/types"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	tmcommon "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/common"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/db"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	cmflags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

const (
	// CfgDebugDisableAddrBookFromGenesis disables populating seed node address book from genesis.
	// This flag is used to disable initial addr book population from genesis in some E2E tests to
	// test the seed node functionality.
	CfgDebugDisableAddrBookFromGenesis = "consensus.tendermint.seed.debug.disable_addr_book_from_genesis"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

type seedService struct {
	seedSrv *tmnode.NodeImpl

	identity *identity.Identity
	doc      *genesis.Document

	stopOnce sync.Once
	quitCh   chan struct{}
}

// Implements consensus.Backend.
func (srv *seedService) Name() string {
	return "tendermint/seed"
}

// Implements consensus.Backend.
func (srv *seedService) Start() error {
	return srv.seedSrv.Start()
}

// Implements consensus.Backend.
func (srv *seedService) Stop() {
	srv.stopOnce.Do(func() {
		close(srv.quitCh)
		_ = srv.seedSrv.Stop()
	})
}

// Implements consensus.Backend.
func (srv *seedService) Quit() <-chan struct{} {
	return srv.quitCh
}

// Implements consensus.Backend.
func (srv *seedService) Cleanup() {
	// No cleanup in particular.
}

// Implements consensus.Backend.
func (srv *seedService) Synced() <-chan struct{} {
	// Seed is always considered synced.
	ch := make(chan struct{})
	close(ch)
	return ch
}

// Implements consensus.Backend.
func (srv *seedService) Mode() consensus.Mode {
	return consensus.ModeSeed
}

// Implements consensus.Backend.
func (srv *seedService) SupportedFeatures() consensus.FeatureMask {
	return consensus.FeatureMask(0)
}

// Implements consensus.Backend.
func (srv *seedService) GetStatus(ctx context.Context) (*consensus.Status, error) {
	status := &consensus.Status{
		Status:   consensus.StatusStateReady,
		Version:  version.ConsensusProtocol,
		Backend:  api.BackendName,
		Mode:     consensus.ModeSeed,
		Features: srv.SupportedFeatures(),
	}

	if srv.seedSrv == nil {
		// Seed node not started yet.
		return status, nil
	}

	// List of consensus peers.
	status.NodePeers = tmcommon.GetPeersFromRPCEnvironment(srv.seedSrv.RPCEnvironment())

	return status, nil
}

// Implements consensus.Backend.
func (srv *seedService) GetNextBlockState(ctx context.Context) (*consensus.NextBlockState, error) {
	return nil, consensus.ErrUnsupported
}

// Implements consensus.Backend.
func (srv *seedService) GetGenesisDocument(ctx context.Context) (*genesis.Document, error) {
	return srv.doc, nil
}

// Implements consensus.Backend.
func (srv *seedService) GetChainContext(ctx context.Context) (string, error) {
	return srv.doc.ChainContext(), nil
}

// Implements consensus.Backend.
func (srv *seedService) GetAddresses() ([]node.ConsensusAddress, error) {
	u, err := tmcommon.GetExternalAddress()
	if err != nil {
		return nil, err
	}

	var addr node.ConsensusAddress
	if err = addr.Address.UnmarshalText([]byte(u.Host)); err != nil {
		return nil, fmt.Errorf("tendermint: failed to parse external address host: %w", err)
	}
	addr.ID = srv.identity.P2PSigner.Public()

	return []node.ConsensusAddress{addr}, nil
}

// Implements consensus.Backend.
func (srv *seedService) Checkpointer() checkpoint.Checkpointer {
	return nil
}

// Implements consensus.Backend.
func (srv *seedService) SubmitEvidence(ctx context.Context, evidence *consensus.Evidence) error {
	return consensus.ErrUnsupported
}

// Implements consensus.Backend.
func (srv *seedService) SubmitTx(ctx context.Context, tx *transaction.SignedTransaction) error {
	return consensus.ErrUnsupported
}

// Implements consensus.Backend.
func (srv *seedService) StateToGenesis(ctx context.Context, height int64) (*genesis.Document, error) {
	return nil, consensus.ErrUnsupported
}

// Implements consensus.Backend.
func (srv *seedService) EstimateGas(ctx context.Context, req *consensus.EstimateGasRequest) (transaction.Gas, error) {
	return 0, consensus.ErrUnsupported
}

// Implements consensus.Backend.
func (srv *seedService) GetBlock(ctx context.Context, height int64) (*consensus.Block, error) {
	return nil, consensus.ErrUnsupported
}

// Implements consensus.Backend.
func (srv *seedService) GetTransactions(ctx context.Context, height int64) ([][]byte, error) {
	return nil, consensus.ErrUnsupported
}

// Implements consensus.Backend.
func (srv *seedService) GetTransactionsWithResults(ctx context.Context, height int64) (*consensus.TransactionsWithResults, error) {
	return nil, consensus.ErrUnsupported
}

// Implements consensus.Backend.
func (srv *seedService) GetUnconfirmedTransactions(ctx context.Context) ([][]byte, error) {
	return nil, consensus.ErrUnsupported
}

// Implements consensus.Backend.
func (srv *seedService) WatchBlocks(ctx context.Context) (<-chan *consensus.Block, pubsub.ClosableSubscription, error) {
	return nil, nil, consensus.ErrUnsupported
}

// Implements consensus.Backend.
func (srv *seedService) GetSignerNonce(ctx context.Context, req *consensus.GetSignerNonceRequest) (uint64, error) {
	return 0, consensus.ErrUnsupported
}

// Implements consensus.Backend.
func (srv *seedService) GetLightBlock(ctx context.Context, height int64) (*consensus.LightBlock, error) {
	return nil, consensus.ErrUnsupported
}

// Implements consensus.Backend.
func (srv *seedService) GetParameters(ctx context.Context, height int64) (*consensus.Parameters, error) {
	return nil, consensus.ErrUnsupported
}

// Implements consensus.Backend.
func (srv *seedService) State() syncer.ReadSyncer {
	return syncer.NopReadSyncer
}

// Implements consensus.Backend.
func (srv *seedService) ConsensusKey() signature.PublicKey {
	return srv.identity.ConsensusSigner.Public()
}

// Implements consensus.Backend.
func (srv *seedService) SubmitTxNoWait(ctx context.Context, tx *transaction.SignedTransaction) error {
	return consensus.ErrUnsupported
}

// Implements consensus.Backend.
func (srv *seedService) RegisterHaltHook(consensus.HaltHook) {
	panic(consensus.ErrUnsupported)
}

// Note: SupportedFeatures() indicates that the backend does not support
// consensus services so the caller is at fault for not adhering to the
// SupportedFeatures flag, in case any of the following methods is called.

// Implements consensus.Backend.
func (srv *seedService) Beacon() beacon.Backend {
	panic(consensus.ErrUnsupported)
}

// Implements consensus.Backend.
func (srv *seedService) KeyManager() keymanager.Backend {
	panic(consensus.ErrUnsupported)
}

// Implements consensus.Backend.
func (srv *seedService) Registry() registry.Backend {
	panic(consensus.ErrUnsupported)
}

// Implements consensus.Backend.
func (srv *seedService) RootHash() roothash.Backend {
	panic(consensus.ErrUnsupported)
}

// Implements consensus.Backend.
func (srv *seedService) Staking() staking.Backend {
	panic(consensus.ErrUnsupported)
}

// Implements consensus.Backend.
func (srv *seedService) Scheduler() scheduler.Backend {
	panic(consensus.ErrUnsupported)
}

// Implements consensus.Backend.
func (srv *seedService) Governance() governance.Backend {
	panic(consensus.ErrUnsupported)
}

// Implements consensus.Backend.
func (srv *seedService) SubmissionManager() consensus.SubmissionManager {
	panic(consensus.ErrUnsupported)
}

// New creates a new seed-only consensus service.
func New(dataDir string, identity *identity.Identity, genesisProvider genesis.Provider) (consensus.Backend, error) {
	var err error

	// This is heavily inspired by https://gitlab.com/polychainlabs/tenderseed
	// and reaches into tendermint to spin up the minimum components required
	// to get the PEX reactor to operate in seed mode.

	srv := &seedService{
		quitCh:   make(chan struct{}),
		identity: identity,
	}

	seedDataDir := filepath.Join(dataDir, "tendermint-seed")
	if err = tmcommon.InitDataDir(seedDataDir); err != nil {
		return nil, fmt.Errorf("tendermint/seed: failed to initialize data dir: %w", err)
	}

	logger := tmcommon.NewLogAdapter(!viper.GetBool(tmcommon.CfgLogDebug))

	p2pCfg := config.DefaultP2PConfig()
	p2pCfg.ListenAddress = viper.GetString(tmcommon.CfgCoreListenAddress)
	p2pCfg.BootstrapPeers = strings.ToLower(strings.Join(viper.GetStringSlice(tmcommon.CfgP2PSeed), ","))
	p2pCfg.ExternalAddress = viper.GetString(tmcommon.CfgCoreExternalAddress)
	p2pCfg.MaxConnections = uint16(viper.GetUint(tmcommon.CfgP2PMaxConnections))
	p2pCfg.SendRate = viper.GetInt64(tmcommon.CfgP2PSendRate)
	p2pCfg.RecvRate = viper.GetInt64(tmcommon.CfgP2PRecvRate)
	p2pCfg.AddrBookStrict = !(viper.GetBool(tmcommon.CfgDebugP2PAddrBookLenient) && cmflags.DebugDontBlameOasis())
	p2pCfg.AllowDuplicateIP = viper.GetBool(tmcommon.CfgDebugP2PAllowDuplicateIP) && cmflags.DebugDontBlameOasis()

	doc, err := genesisProvider.GetGenesisDocument()
	if err != nil {
		return nil, fmt.Errorf("tendermint/seed: failed to get genesis document: %w", err)
	}
	srv.doc = doc
	tmGenesisProvider := func() (*tmtypes.GenesisDoc, error) {
		return api.GetTendermintGenesisDocument(genesisProvider)
	}

	if !(viper.GetBool(CfgDebugDisableAddrBookFromGenesis) && cmflags.DebugDontBlameOasis()) {
		// Since we don't have access to the address book, add the genesis nodes
		// to the bootstrap peers instead.
		var addrs []string
		for _, v := range doc.Registry.Nodes {
			var openedNode node.Node
			if grr := v.Open(registry.RegisterGenesisNodeSignatureContext, &openedNode); grr != nil {
				return nil, fmt.Errorf("tendermint/seed: failed to verify validator: %w", grr)
			}
			// TODO: This should cross check that the entity is valid.
			if !openedNode.HasRoles(node.RoleValidator) {
				continue
			}

			var tmvAddr *tmtypes.NetAddress
			tmvAddr, grr := api.NodeToP2PAddr(&openedNode)
			if grr != nil {
				logger.Error("failed to reformat genesis validator address",
					"err", grr,
				)
				continue
			}

			addrs = append(addrs, tmvAddr.String())
		}
		if len(addrs) > 0 {
			if len(p2pCfg.BootstrapPeers) > 0 {
				p2pCfg.BootstrapPeers = p2pCfg.BootstrapPeers + ","
			}
			p2pCfg.BootstrapPeers = p2pCfg.BootstrapPeers + strings.Join(addrs, ",")
		}
	}

	nodeCfg := config.DefaultConfig()
	nodeCfg.Mode = config.ModeSeed
	nodeCfg.Moniker = "oasis-seed-" + identity.NodeSigner.Public().String()
	nodeCfg.Mempool.Version = config.MempoolV1
	nodeCfg.P2P = p2pCfg
	nodeCfg.SetRoot(seedDataDir)

	tmpk := crypto.SignerToTendermint(identity.P2PSigner)
	nodeKey := tmtypes.NodeKey{ID: tmtypes.NodeIDFromPubKey(tmpk.PubKey()), PrivKey: tmpk}

	dbProvider, err := db.GetProvider()
	if err != nil {
		return nil, fmt.Errorf("tendermint/seed: failed to get database provider")
	}

	srv.seedSrv, err = tmnode.MakeSeedNode(nodeCfg, dbProvider, nodeKey, tmGenesisProvider, logger)
	if err != nil {
		return nil, err
	}

	return srv, nil
}

func init() {
	Flags.Bool(CfgDebugDisableAddrBookFromGenesis, false, "disable populating address book with genesis validators")

	_ = Flags.MarkHidden(CfgDebugDisableAddrBookFromGenesis)

	_ = viper.BindPFlags(Flags)
}
