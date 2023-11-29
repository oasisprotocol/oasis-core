package registry

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/eapache/channels"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/quote"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	consensusResults "github.com/oasisprotocol/oasis-core/go/consensus/api/transaction/results"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/multi"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	runtimeKeymanager "github.com/oasisprotocol/oasis-core/go/runtime/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

const (
	// notifyTimeout is the maximum time to wait for a notification to be processed by the runtime.
	notifyTimeout = 10 * time.Second

	// retryInterval is the time interval used between failed key manager updates.
	retryInterval = time.Second

	// minAttestationInterval is the minimum attestation interval.
	minAttestationInterval = 5 * time.Minute
)

// RuntimeHostNode provides methods for nodes that need to host runtimes.
type RuntimeHostNode struct {
	sync.Mutex

	factory  RuntimeHostHandlerFactory
	notifier protocol.Notifier

	agg           *multi.Aggregate
	runtime       host.RichRuntime
	runtimeNotify chan struct{}
}

// ProvisionHostedRuntime provisions the configured runtime.
//
// This method may return before the runtime is fully provisioned. The returned runtime will not be
// started automatically, you must call Start explicitly.
func (n *RuntimeHostNode) ProvisionHostedRuntime(ctx context.Context) (host.RichRuntime, protocol.Notifier, error) {
	runtime := n.factory.GetRuntime()

	// Ensure registry descriptor is ready as it is required for obtaining Host configuration.
	_, err := runtime.RegistryDescriptor(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to wait for registry descriptor: %w", err)
	}
	cfgs, provisioner, err := runtime.Host()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get runtime host: %w", err)
	}

	// Provision the handler that implements the host RHP methods.
	msgHandler := n.factory.NewRuntimeHostHandler()

	rts := make(map[version.Version]host.Runtime)
	for version, cfg := range cfgs {
		rtCfg := *cfg
		rtCfg.MessageHandler = msgHandler

		// Provision the runtime.
		if rts[version], err = provisioner.NewRuntime(rtCfg); err != nil {
			return nil, nil, fmt.Errorf("failed to provision runtime version %s: %w", version, err)
		}
	}

	agg, err := multi.New(ctx, runtime.ID(), rts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to provision aggregate runtime: %w", err)
	}

	notifier := n.factory.NewRuntimeHostNotifier(ctx, agg)
	rr := host.NewRichRuntime(agg)

	n.Lock()
	n.agg = agg.(*multi.Aggregate)
	n.runtime = rr
	n.notifier = notifier
	n.Unlock()

	close(n.runtimeNotify)

	return rr, notifier, nil
}

// GetHostedRuntime returns the provisioned hosted runtime (if any).
func (n *RuntimeHostNode) GetHostedRuntime() host.RichRuntime {
	n.Lock()
	defer n.Unlock()

	return n.runtime
}

// WaitHostedRuntime waits for the hosted runtime to be provisioned and returns it.
func (n *RuntimeHostNode) WaitHostedRuntime(ctx context.Context) (host.RichRuntime, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-n.runtimeNotify:
	}

	return n.GetHostedRuntime(), nil
}

// GetHostedRuntimeCapabilityTEE returns the CapabilityTEE for a specific runtime version.
func (n *RuntimeHostNode) GetHostedRuntimeCapabilityTEE(version version.Version) (*node.CapabilityTEE, error) {
	n.Lock()
	agg := n.agg
	n.Unlock()

	if agg == nil {
		return nil, fmt.Errorf("runtime not available")
	}

	rt, err := agg.GetVersion(version)
	if err != nil {
		return nil, err
	}
	return rt.GetCapabilityTEE()
}

// SetHostedRuntimeVersion sets the currently active and next versions for the hosted runtime.
func (n *RuntimeHostNode) SetHostedRuntimeVersion(active version.Version, next *version.Version) error {
	n.Lock()
	agg := n.agg
	n.Unlock()

	if agg == nil {
		return fmt.Errorf("runtime not available")
	}

	return agg.SetVersion(active, next)
}

// RuntimeHostHandlerFactory is an interface that can be used to create new runtime handlers and
// notifiers when provisioning hosted runtimes.
type RuntimeHostHandlerFactory interface {
	// GetRuntime returns the registered runtime for which a runtime host handler is to be created.
	GetRuntime() Runtime

	// NewRuntimeHostHandler creates a new runtime host handler.
	NewRuntimeHostHandler() protocol.Handler

	// NewRuntimeHostNotifier creates a new runtime host notifier.
	NewRuntimeHostNotifier(ctx context.Context, host host.Runtime) protocol.Notifier
}

// NewRuntimeHostNode creates a new runtime host node.
func NewRuntimeHostNode(factory RuntimeHostHandlerFactory) (*RuntimeHostNode, error) {
	return &RuntimeHostNode{
		factory:       factory,
		runtimeNotify: make(chan struct{}),
	}, nil
}

var (
	errMethodNotSupported   = errors.New("method not supported")
	errEndpointNotSupported = errors.New("endpoint not supported")
)

// RuntimeHostHandlerEnvironment is the host environment interface.
type RuntimeHostHandlerEnvironment interface {
	// GetKeyManagerClient returns the key manager client for this runtime.
	GetKeyManagerClient() (runtimeKeymanager.Client, error)

	// GetTxPool returns the transaction pool for this runtime.
	GetTxPool() (txpool.TransactionPool, error)

	// GetNodeIdentity returns the identity of a node running this runtime.
	GetNodeIdentity() (*identity.Identity, error)

	// GetLightClient returns the consensus light client.
	GetLightClient() (consensus.LightClient, error)
}

// RuntimeHostHandler is a runtime host handler suitable for compute runtimes. It provides the
// required set of methods for interacting with the outside world.
type runtimeHostHandler struct {
	env       RuntimeHostHandlerEnvironment
	runtime   Runtime
	consensus consensus.Backend
}

func (h *runtimeHostHandler) handleHostRPCCall(
	ctx context.Context,
	rq *protocol.HostRPCCallRequest,
) (*protocol.HostRPCCallResponse, error) {
	switch rq.Endpoint {
	case runtimeKeymanager.EnclaveRPCEndpoint:
		// Call into the remote key manager.
		kmCli, err := h.env.GetKeyManagerClient()
		if err != nil {
			return nil, err
		}
		res, node, err := kmCli.CallEnclave(ctx, rq.Request, rq.Nodes, rq.Kind, rq.PeerFeedback)
		if err != nil {
			return nil, err
		}
		// Don't send node identity if the runtime doesn't support explicit key manager RPC calls.
		if rq.Nodes == nil {
			return &protocol.HostRPCCallResponse{
				Response: res,
			}, nil
		}
		return &protocol.HostRPCCallResponse{
			Response: res,
			Node:     &node,
		}, nil
	default:
		return nil, errEndpointNotSupported
	}
}

func (h *runtimeHostHandler) handleHostStorageSync(
	ctx context.Context,
	rq *protocol.HostStorageSyncRequest,
) (*protocol.HostStorageSyncResponse, error) {
	var rs syncer.ReadSyncer
	switch rq.Endpoint {
	case protocol.HostStorageEndpointRuntime:
		// Runtime storage.
		rs = h.runtime.Storage()
		if rs == nil {
			// May be unsupported for unmanaged runtimes like the key manager.
			return nil, errEndpointNotSupported
		}
	case protocol.HostStorageEndpointConsensus:
		// Consensus state storage.
		rs = h.consensus.State()
	default:
		return nil, errEndpointNotSupported
	}

	var rsp *storage.ProofResponse
	var err error
	switch {
	case rq.SyncGet != nil:
		rsp, err = rs.SyncGet(ctx, rq.SyncGet)
	case rq.SyncGetPrefixes != nil:
		rsp, err = rs.SyncGetPrefixes(ctx, rq.SyncGetPrefixes)
	case rq.SyncIterate != nil:
		rsp, err = rs.SyncIterate(ctx, rq.SyncIterate)
	default:
		return nil, errMethodNotSupported
	}
	if err != nil {
		return nil, err
	}

	return &protocol.HostStorageSyncResponse{ProofResponse: rsp}, nil
}

func (h *runtimeHostHandler) handleHostLocalStorageGet(
	rq *protocol.HostLocalStorageGetRequest,
) (*protocol.HostLocalStorageGetResponse, error) {
	value, err := h.runtime.LocalStorage().Get(rq.Key)
	if err != nil {
		return nil, err
	}
	return &protocol.HostLocalStorageGetResponse{Value: value}, nil
}

func (h *runtimeHostHandler) handleHostLocalStorageSet(
	rq *protocol.HostLocalStorageSetRequest,
) (*protocol.Empty, error) {
	if err := h.runtime.LocalStorage().Set(rq.Key, rq.Value); err != nil {
		return nil, err
	}
	return &protocol.Empty{}, nil
}

func (h *runtimeHostHandler) handleHostFetchConsensusBlock(
	ctx context.Context,
	rq *protocol.HostFetchConsensusBlockRequest,
) (*protocol.HostFetchConsensusBlockResponse, error) {
	// Invoke the light client. If a local full node is available the light
	// client will internally query the local node first.
	lc, err := h.env.GetLightClient()
	if err != nil {
		return nil, err
	}
	blk, _, err := lc.GetLightBlock(ctx, int64(rq.Height))
	if err != nil {
		return nil, fmt.Errorf("light block fetch failure: %w", err)
	}

	// Add extra signatures collected offline to Eden genesis light block.
	chainContext, err := h.consensus.GetChainContext(ctx)
	if err != nil {
		return nil, err
	}
	edenChainContext := "bb3d748def55bdfb797a2ac53ee6ee141e54cd2ab2dc2375f4a0703a178e6e55"
	edenGenesisHeight := uint64(16817956)
	if chainContext == edenChainContext && rq.Height == edenGenesisHeight {
		var pb cmtproto.LightBlock
		if err = pb.Unmarshal(blk.Meta); err != nil {
			return nil, fmt.Errorf("failed to unmarshal cometbft light block: %w", err)
		}

		// Missing signatures.
		encSigs := map[int]string{
			3:   "",                                                                                                                                 // 1D695FD854E1D39EFB14B6051484AB3A3E946D42 Mars Staking | Long term fee 1%
			6:   "",                                                                                                                                 // DB155AD2D2B42EBB8D96171421F71CEBFCCE9443 GoStaking
			9:   "2a393a32f69087fc6bcd7aa60d3a1c9a427229b0e851a89610598538ab712c81d2a61d8114dbff8b2a3ad109ae964cb72ea73f651c1699a81580dfdd5acdf30c", // 3C7535AD5A1CEE0DF1F5A9D0FBB7F115597D694D Bit Cat🐱
			11:  "c2400d5300267aeef1c6841387ab7f4e52678465446963052744a9c557db5d4956cebd440c0e38e05f7beabfa07c752043db6e5fb9df417b5e4e062ec525f00b", // B98AC6369C28A836D1767B5FB0DDB09B641F59FD Doorgod
			13:  "33b7b68929ff47ea7cde731fbd243564e3bd1c3b1ce3f877907858e52c9392733b422b9eb856ec1c2edf8a77fade798a6813f35601e950a015dda6ad9c943201", // D7E17A746BA033183C6D631DBEBF95593FF12303 Spectrum Staking
			15:  "02524bd3e8512ad57504f6f090322e7c8640b2df6edaf69f519fd0ff543e8306c19256ec08f11b3371f504cb5e064c3c80bdff99ab1190789eda1b5782c89a08", // 46B86E7BAAEBE7083422979EC56DDC9B332A9236 Princess Stake
			16:  "",                                                                                                                                 // A3077AE4E4622C68E41E8BF9C6CDAC3396478D3B Everstake
			18:  "",                                                                                                                                 // 031530A0C5735775A2B75137DCB2B3A58E3DCE21 Tessellated Geometry
			20:  "faa447cbb617fb7c7d603cba86e42d7e9c04e292030ec6921217d629081d1a4cef8193161f5d573645f03844776bbe9a8ab2483463868406efdbd200775a3d01", // 139F7714CD1FC8012B68D79BCB5CBDAF25C0139F Dobrynya Hukutu4
			21:  "",                                                                                                                                 // 44C6F655469D0FB5BAC6AA95DAF21566911C5346 <none>
			22:  "238a8cbed6b4515ed17defb89b38e02c84e2b25da61ec09cf73d7b99009ced290e34535257e2732ff3bc699a62aa1ae9850e99dcd4e75aca985f73cf57f67203", // AFA000D76FAE365C7AFCF77EA378DA2AD51AA852 Alexander (aka Bambarello) Validator
			32:  "0d5128d9018f59a8880c893ed86b4b41cd5fe8eedf11f39621ee1dd89a07292b99fde5419d63a1766ff6df147d0e48acc8178f1965088234d8291815cc875406", // 5D9CCE6B571A19368F49986A55A084DAFC16FF67 glebanyy
			36:  "",                                                                                                                                 // E13CCC629C674390A001CF09896F2E579C5BC0B8 Ocean Stake
			37:  "",                                                                                                                                 // CB7C4EFA3CC0CF13D5D276F3933A3FCA41B48DC9 AutoStake 🛡️ Slash Protected
			39:  "30c4ec9766caf84945efc3f130e41c8879704d3140805559cce773a00f49fe7a1d71233c86cbf3bf334ca178dcc252ef92f06d3c75db80aa506c848989bb4309", // AC6FD590781448186B9D5990E7D8A5154E32CC97 0base.vc
			40:  "",                                                                                                                                 // C0F7D1DF00612C3099B05020802891C8F142E7C5 Staky.io
			42:  "",                                                                                                                                 // 672FD177BE6DCE12743638C338EDF53EDA3E5C92 Hashed x DELIGHT
			43:  "",                                                                                                                                 // E81A0385D14F085B778A6CA065BB71CEDE8BD1BB itokenpool
			58:  "33d3402c351fcb15bdbc69be53dba8beac4a4005a51c9f1edc4479a3924aa4cdaedfdc2ab44792aaf4123945859cc88874dc9b9186f5ecf2e8a109bfca05710b", // 916DC43DC0D9D80669A4CF096F82F45618A11D6F Stardust
			61:  "",                                                                                                                                 // C6A279F20AFE19744F163FC252E7B8485839C7D6 Wetez
			62:  "",                                                                                                                                 // 7954EE2396125ED080B0EF500D71ECA7176F0C00 <none>
			63:  "ccf304e4737e0363c0b1d462d87674987b1a4c9566c22a8a70f6455a7525a040f02024e7aa43f8e1a16e89d595148e7d1dd2ac2a1e0ce84c2789dc635096280b", // CBB0BDE73E1ECCCA26CA9F99A2251B5DCCBCA803 <none>
			65:  "",                                                                                                                                 // 4F4B50D08E0D5CE2D2FF0B0C7A50DD52E11B791B DCC Capital
			66:  "",                                                                                                                                 // B600F97DD0D38027824EF9DF5EF7EEE235025A15 HashQuark
			67:  "",                                                                                                                                 // DD84C10CE13D57B69DF63C992DC6E34AEAA4F88B WolfEdge Capital
			68:  "",                                                                                                                                 // 396361E55E55FA3C6BFAA0C44E1F41B4DB7D1187 <none>
			69:  "",                                                                                                                                 // 198FEE1CDDF99D4EC9246ACEA150131E39319D04 <none>
			72:  "",                                                                                                                                 // C130071B3ACC17434AC02E4E9703C40B060518DD BlockOG Capital
			73:  "",                                                                                                                                 // 90D04059E345E74F5CFF9F82B33E32FE02692B98 Datax Staking
			74:  "",                                                                                                                                 // 8114E8BE22380A11996CEA93D98A0E1C8BA323A2 Strata One
			75:  "",                                                                                                                                 // ADA4C52F122FD76ACBFD1D658EF7A3A336D6AFE9 InfStones
			76:  "",                                                                                                                                 // 7AC5014F77E02CC9B503F5D748BEA2D889AF3F16 <none>
			77:  "",                                                                                                                                 // 28B637520B7DC7853FB0259A104FFF2E0EC165B1 Ubik Capital
			79:  "",                                                                                                                                 // 8A40E18A0904D1876AF5557A0C156AB2D4E05893 <none>
			82:  "",                                                                                                                                 // D6F5A43D5C99CC6C3D63AE88AB3B287C01AE795B <none>
			83:  "",                                                                                                                                 // 9B5FE068239F5C866903DAF2CA7BCBCABDD314E4 <none>
			84:  "",                                                                                                                                 // 86AE5099F1313FA685B1856F1952F982155546ED Aptemuyc🌹
			85:  "",                                                                                                                                 // 8885B8729A2EB95EBBC1D48CB86FD0C29979AB24 hybridx.exchange
			87:  "",                                                                                                                                 // 60A4964BE14FF231A3494AA1D4077F483E68EDE5 Blockscale - Planet-Scale Blockchain Services
			91:  "",                                                                                                                                 // 250CEEEA6C409B23F6107D32A01CD0A6AF0FE6EC Bi23 Labs
			93:  "",                                                                                                                                 // 9EC5FC5676DA8167CD2BEDF2DE91EA97745BCF6B 01node
			94:  "",                                                                                                                                 // 44687C15D1BD79E7D369C0ADEFDAEC218B5B7A11 Kiln
			95:  "",                                                                                                                                 // BD798061A0F78C0AE199F28BE0ACC98FBC0EFD3B <none>
			96:  "",                                                                                                                                 // BB7DB41FFF58D8EF6199616EF13E05D952B7BD73 Terminet
			97:  "",                                                                                                                                 // A743D637323C6ABFFB624858894366AFE2CF385F Maria Mirabella❤️ ROSE
			98:  "",                                                                                                                                 // 75EBFB35260AD902BC16F15ACD393293C19DDC36 <none>
			99:  "",                                                                                                                                 // 3B9EA83997FA0434AA9AD0AE19EFE6003EBCE348 Coinpayu
			100: "",                                                                                                                                 // 636CB5449716C3F320257466277097E0F9BA8514 RoseDrop
			101: "",                                                                                                                                 // E509726BE1CFFB3EADDF0903A8A9E917544DD6E9 AndromedaPool | Zero fee to 2025
			102: "",                                                                                                                                 // 0F3B35C317478369535094440A5E41E2DE2DB05A Hammerfest
			104: "",                                                                                                                                 // BFD76834515381BDC8B542B9EEA5BFB5F4B2DA02 0% Fee StakeSeeker by BTCS
			105: "",                                                                                                                                 // 88399F3514B019F93BF924395A275D7C017DD8EF Hyperblockspro
			106: "",                                                                                                                                 // FACE3B7A56347F073429544A409C29EE77A44EEC Second State
			107: "ab8fc5b6a852f5847805e8653aa590e982bcc48d45887a036bb2fc33fb673f5c6e69119a9feaa9c04a97fa76442f6a10198250f452a45d226d267bd120094d00", // E13306587B4245312A57F696DCB5BC407E0CD0F4 LaunchGarden
			108: "",                                                                                                                                 // A07B898C4B997CEE60891A05A647AADD557C8FCE Validator.ONE | 0% Fee | Trusted Validator
			110: "",                                                                                                                                 // CEA0F5491682A80315A81997AAF56C40F386CA22 <none>
			112: "",                                                                                                                                 // BD12B6312E58E2859E7C6F4E092DB9269232F99F Oasis@UBC
			113: "",                                                                                                                                 // 2ABE1491367ABE4B7C5FB2292ADF5E2FFFC99E59 Moonstake
			115: "07417909023b5901fb6156b8b9555ee8ff286f5fa2a6a0da74d0dc5bd75b14d327c00d40e645bf5c79bef2d1d1c9e0ea8aac5278a803e671a13f995b0137f107", // F8B244ADA2FC5FC3E864838375391D470A29CC39 CryptoSJ.net
			116: "",                                                                                                                                 // B5391717B04E44F931FF70ACEB54AA84B38BD2B9 StakeHaven
			117: "",                                                                                                                                 // 7EDDB9611E5C1496C99B0DCA3D133757540DDBF1 Colossus
		}

		// Timestamp of missing signatures.
		timeString := "2023-11-29 11:25:17.649247857 +0000 UTC"
		layout := "2006-01-02 15:04:05.999999999 -0700 MST"
		timestamp, err := time.Parse(layout, timeString)
		if err != nil {
			return nil, err
		}

		// Fetch validator address from the validator set.
		valset := pb.GetValidatorSet()
		vals := valset.GetValidators()

		for index, encSig := range encSigs {
			if encSig == "" {
				continue
			}
			if index >= len(pb.SignedHeader.Commit.Signatures) {
				return nil, fmt.Errorf("cometbft light block signature index %d out of bounds", index)
			}
			if len(pb.SignedHeader.Commit.Signatures[index].Signature) > 0 {
				return nil, fmt.Errorf("cometbft light block signature %d already set", index)
			}

			sig, err := hex.DecodeString(encSig)
			if err != nil {
				return nil, fmt.Errorf("failed to decode cometbft light block signature: %w", err)
			}

			comSig := cmtproto.CommitSig{
				BlockIdFlag:      2,
				ValidatorAddress: vals[index].GetAddress(),
				Timestamp:        timestamp,
				Signature:        sig,
			}
			pb.SignedHeader.Commit.Signatures[index] = comSig
		}

		meta, err := pb.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal cometbft light block: %w", err)
		}

		blk.Meta = meta
	}

	return &protocol.HostFetchConsensusBlockResponse{Block: *blk}, nil
}

func (h *runtimeHostHandler) handleHostFetchConsensusEvents(
	ctx context.Context,
	rq *protocol.HostFetchConsensusEventsRequest,
) (*protocol.HostFetchConsensusEventsResponse, error) {
	var evs []*consensusResults.Event
	switch rq.Kind {
	case protocol.EventKindStaking:
		sevs, err := h.consensus.Staking().GetEvents(ctx, int64(rq.Height))
		if err != nil {
			return nil, err
		}
		evs = make([]*consensusResults.Event, 0, len(sevs))
		for _, sev := range sevs {
			evs = append(evs, &consensusResults.Event{Staking: sev})
		}
	case protocol.EventKindRegistry:
		revs, err := h.consensus.Registry().GetEvents(ctx, int64(rq.Height))
		if err != nil {
			return nil, err
		}
		evs = make([]*consensusResults.Event, 0, len(revs))
		for _, rev := range revs {
			evs = append(evs, &consensusResults.Event{Registry: rev})
		}
	case protocol.EventKindRootHash:
		revs, err := h.consensus.RootHash().GetEvents(ctx, int64(rq.Height))
		if err != nil {
			return nil, err
		}
		evs = make([]*consensusResults.Event, 0, len(revs))
		for _, rev := range revs {
			evs = append(evs, &consensusResults.Event{RootHash: rev})
		}
	case protocol.EventKindGovernance:
		gevs, err := h.consensus.Governance().GetEvents(ctx, int64(rq.Height))
		if err != nil {
			return nil, err
		}
		evs = make([]*consensusResults.Event, 0, len(gevs))
		for _, gev := range gevs {
			evs = append(evs, &consensusResults.Event{Governance: gev})
		}
	default:
		return nil, errMethodNotSupported
	}
	return &protocol.HostFetchConsensusEventsResponse{Events: evs}, nil
}

func (h *runtimeHostHandler) handleHostFetchGenesisHeight(
	ctx context.Context,
) (*protocol.HostFetchGenesisHeightResponse, error) {
	doc, err := h.consensus.GetGenesisDocument(ctx)
	if err != nil {
		return nil, err
	}
	return &protocol.HostFetchGenesisHeightResponse{Height: uint64(doc.Height)}, nil
}

func (h *runtimeHostHandler) handleHostFetchTxBatch(
	rq *protocol.HostFetchTxBatchRequest,
) (*protocol.HostFetchTxBatchResponse, error) {
	txPool, err := h.env.GetTxPool()
	if err != nil {
		return nil, err
	}

	batch := txPool.GetSchedulingExtra(rq.Offset, rq.Limit)
	raw := make([][]byte, 0, len(batch))
	for _, tx := range batch {
		raw = append(raw, tx.Raw())
	}

	return &protocol.HostFetchTxBatchResponse{Batch: raw}, nil
}

func (h *runtimeHostHandler) handleHostFetchBlockMetadataTx(
	ctx context.Context,
	rq *protocol.HostFetchBlockMetadataTxRequest,
) (*protocol.HostFetchBlockMetadataTxResponse, error) {
	tps, err := h.consensus.GetTransactionsWithProofs(ctx, int64(rq.Height))
	if err != nil {
		return nil, err
	}

	// The block metadata transaction should be located at the end of the block.
	for i := len(tps.Transactions) - 1; i >= 0; i-- {
		rawTx := tps.Transactions[i]

		var sigTx transaction.SignedTransaction
		if err = cbor.Unmarshal(rawTx, &sigTx); err != nil {
			continue
		}

		// Signature already verified by the validators, skipping.

		var tx transaction.Transaction
		if err = cbor.Unmarshal(sigTx.Blob, &tx); err != nil {
			continue
		}

		if tx.Method != consensus.MethodMeta {
			continue
		}

		return &protocol.HostFetchBlockMetadataTxResponse{
			SignedTx: &sigTx,
			Proof: &transaction.Proof{
				Height:   int64(rq.Height),
				RawProof: tps.Proofs[i],
			},
		}, nil
	}

	return nil, fmt.Errorf("block metadata transaction not found")
}

func (h *runtimeHostHandler) handleHostProveFreshness(
	ctx context.Context,
	rq *protocol.HostProveFreshnessRequest,
) (*protocol.HostProveFreshnessResponse, error) {
	identity, err := h.env.GetNodeIdentity()
	if err != nil {
		return nil, err
	}
	tx := registry.NewProveFreshnessTx(0, nil, rq.Blob)
	sigTx, proof, err := consensus.SignAndSubmitTxWithProof(ctx, h.consensus, identity.NodeSigner, tx)
	if err != nil {
		return nil, err
	}

	return &protocol.HostProveFreshnessResponse{
		SignedTx: sigTx,
		Proof:    proof,
	}, nil
}

func (h *runtimeHostHandler) handleHostIdentity() (*protocol.HostIdentityResponse, error) {
	identity, err := h.env.GetNodeIdentity()
	if err != nil {
		return nil, err
	}

	return &protocol.HostIdentityResponse{
		NodeID: identity.NodeSigner.Public(),
	}, nil
}

// Implements protocol.Handler.
func (h *runtimeHostHandler) Handle(ctx context.Context, rq *protocol.Body) (*protocol.Body, error) {
	var (
		rsp protocol.Body
		err error
	)

	switch {
	case rq.HostRPCCallRequest != nil:
		// RPC.
		rsp.HostRPCCallResponse, err = h.handleHostRPCCall(ctx, rq.HostRPCCallRequest)
	case rq.HostStorageSyncRequest != nil:
		// Storage sync.
		rsp.HostStorageSyncResponse, err = h.handleHostStorageSync(ctx, rq.HostStorageSyncRequest)
	case rq.HostLocalStorageGetRequest != nil:
		// Local storage get.
		rsp.HostLocalStorageGetResponse, err = h.handleHostLocalStorageGet(rq.HostLocalStorageGetRequest)
	case rq.HostLocalStorageSetRequest != nil:
		// Local storage set.
		rsp.HostLocalStorageSetResponse, err = h.handleHostLocalStorageSet(rq.HostLocalStorageSetRequest)
	case rq.HostFetchConsensusBlockRequest != nil:
		// Consensus light client.
		rsp.HostFetchConsensusBlockResponse, err = h.handleHostFetchConsensusBlock(ctx, rq.HostFetchConsensusBlockRequest)
	case rq.HostFetchConsensusEventsRequest != nil:
		// Consensus events.
		rsp.HostFetchConsensusEventsResponse, err = h.handleHostFetchConsensusEvents(ctx, rq.HostFetchConsensusEventsRequest)
	case rq.HostFetchGenesisHeightRequest != nil:
		// Consensus genesis height.
		rsp.HostFetchGenesisHeightResponse, err = h.handleHostFetchGenesisHeight(ctx)
	case rq.HostFetchTxBatchRequest != nil:
		// Transaction pool.
		rsp.HostFetchTxBatchResponse, err = h.handleHostFetchTxBatch(rq.HostFetchTxBatchRequest)
	case rq.HostFetchBlockMetadataTxRequest != nil:
		// Block metadata.
		rsp.HostFetchBlockMetadataTxResponse, err = h.handleHostFetchBlockMetadataTx(ctx, rq.HostFetchBlockMetadataTxRequest)
	case rq.HostProveFreshnessRequest != nil:
		// Prove freshness.
		rsp.HostProveFreshnessResponse, err = h.handleHostProveFreshness(ctx, rq.HostProveFreshnessRequest)
	case rq.HostIdentityRequest != nil:
		// Host identity.
		rsp.HostIdentityResponse, err = h.handleHostIdentity()
	default:
		err = errMethodNotSupported
	}

	if err != nil {
		return nil, err
	}
	return &rsp, nil
}

// runtimeHostNotifier is a runtime host notifier suitable for compute runtimes. It handles things
// like key manager policy updates.
type runtimeHostNotifier struct {
	sync.Mutex

	ctx context.Context

	stopCh chan struct{}

	started   bool
	runtime   Runtime
	host      host.RichRuntime
	consensus consensus.Backend

	logger *logging.Logger
}

func (n *runtimeHostNotifier) watchPolicyUpdates() {
	// Subscribe to runtime descriptor updates.
	dscCh, dscSub, err := n.runtime.WatchRegistryDescriptor()
	if err != nil {
		n.logger.Error("failed to subscribe to registry descriptor updates",
			"err", err,
		)
		return
	}
	defer dscSub.Close()

	var (
		kmRtID *common.Namespace
		done   bool
	)

	for !done {
		done = func() bool {
			// Start watching key manager policy updates.
			var wg sync.WaitGroup
			defer wg.Wait()

			ctx, cancel := context.WithCancel(n.ctx)
			defer cancel()

			wg.Add(1)
			go func(kmRtID *common.Namespace) {
				defer wg.Done()
				n.watchKmPolicyUpdates(ctx, kmRtID)
			}(kmRtID)

			// Restart the updater if the runtime changes the key manager. This should happen
			// at most once as runtimes are not allowed to change the manager once set.
			for {
				select {
				case <-n.ctx.Done():
					n.logger.Debug("context canceled")
					return true
				case <-n.stopCh:
					n.logger.Debug("termination requested")
					return true
				case rtDsc := <-dscCh:
					n.logger.Debug("got registry descriptor update")

					if rtDsc.Kind != registry.KindCompute {
						return true
					}

					if kmRtID.Equal(rtDsc.KeyManager) {
						break
					}

					kmRtID = rtDsc.KeyManager
					return false
				}
			}
		}()
	}
}

func (n *runtimeHostNotifier) watchKmPolicyUpdates(ctx context.Context, kmRtID *common.Namespace) {
	// No need to watch anything if key manager is not set.
	if kmRtID == nil {
		return
	}

	n.logger.Debug("watching key manager policy updates", "keymanager", kmRtID)

	// Subscribe to key manager status updates (policy might change).
	stCh, stSub := n.consensus.KeyManager().WatchStatuses()
	defer stSub.Close()

	// Subscribe to epoch transitions (quote policy might change).
	epoCh, sub, err := n.consensus.Beacon().WatchEpochs(ctx)
	if err != nil {
		n.logger.Error("failed to watch epochs",
			"err", err,
		)
		return
	}
	defer sub.Close()

	// Subscribe to runtime host events (policies will be lost on restarts).
	evCh, evSub, err := n.host.WatchEvents(n.ctx)
	if err != nil {
		n.logger.Error("failed to subscribe to runtime host events",
			"err", err,
		)
		return
	}
	defer evSub.Close()

	retryTicker := time.NewTicker(retryInterval)
	defer retryTicker.Stop()

	var (
		statusUpdated      = true
		quotePolicyUpdated = true
		runtimeInfoUpdated = false
	)

	var (
		st *keymanager.Status
		sc *node.SGXConstraints
		vi *registry.VersionInfo
		ri *protocol.RuntimeInfoResponse
	)

	for {
		// Fetch runtime info so that we know which features the current runtime version supports.
		if !runtimeInfoUpdated {
			if ri, err = n.host.GetInfo(ctx); err != nil {
				n.logger.Error("failed to fetch runtime info",
					"err", err,
				)
				return
			}
			runtimeInfoUpdated = true
		}

		// Make sure that we actually have a new status.
		if !statusUpdated && st != nil {
			switch {
			case ri.Features.KeyManagerStatusUpdates:
				if err = n.updateKeyManagerStatus(ctx, st); err == nil {
					statusUpdated = true
				}
			case st.Policy != nil:
				if err = n.updateKeyManagerPolicy(ctx, st.Policy); err == nil {
					statusUpdated = true
				}
			}
		}

		// Make sure that we actually have a new quote policy and that the current runtime version
		// supports quote policy updates.
		if !quotePolicyUpdated && sc != nil && sc.Policy != nil && ri.Features.KeyManagerQuotePolicyUpdates {
			if err = n.updateKeyManagerQuotePolicy(ctx, sc.Policy); err == nil {
				quotePolicyUpdated = true
			}
		}

		select {
		case <-ctx.Done():
			return
		case newSt := <-stCh:
			// Ignore status updates for a different key manager.
			if !newSt.ID.Equal(kmRtID) {
				continue
			}
			st = newSt

			statusUpdated = false
		case epoch := <-epoCh:
			// Check if the key manager was redeployed, as that is when a new quote policy might
			// take effect.
			dsc, err := n.consensus.Registry().GetRuntime(ctx, &registry.GetRuntimeQuery{
				Height: consensus.HeightLatest,
				ID:     *kmRtID,
			})
			if err != nil {
				n.logger.Error("failed to query key manager runtime descriptor",
					"err", err,
				)
				continue
			}

			// Quote polices can only be set on SGX hardwares.
			if dsc.TEEHardware != node.TEEHardwareIntelSGX {
				continue
			}

			// No need to update the policy if the key manager is sill running the same version.
			newVi := dsc.ActiveDeployment(epoch)
			if newVi.Equal(vi) {
				continue
			}
			vi = newVi

			// Parse SGX constraints.
			var newSc node.SGXConstraints
			if err := cbor.Unmarshal(vi.TEE, &newSc); err != nil {
				n.logger.Error("malformed SGX constraints",
					"err", err,
				)
				continue
			}
			sc = &newSc

			quotePolicyUpdated = false
		case ev := <-evCh:
			// Runtime host changes, make sure to update the policies if runtime is restarted.
			if ev.Started == nil && ev.Updated == nil {
				continue
			}

			statusUpdated = false
			quotePolicyUpdated = false
			runtimeInfoUpdated = false
		case <-retryTicker.C:
			// Retry updates if some of them failed. When using CometBFT as a backend service
			// the host will see the new state one block before the consensus verifier as the former
			// sees the block H after it is executed while the latter needs to trust the block H
			// first by verifying the signatures which are only available after the block H+1
			// finalizes.
		}
	}
}

func (n *runtimeHostNotifier) updateKeyManagerStatus(ctx context.Context, status *keymanager.Status) error {
	n.logger.Debug("got key manager status update", "status", status)

	req := &protocol.Body{RuntimeKeyManagerStatusUpdateRequest: &protocol.RuntimeKeyManagerStatusUpdateRequest{
		Status: *status,
	}}

	ctx, cancel := context.WithTimeout(ctx, notifyTimeout)
	defer cancel()

	if _, err := n.host.Call(ctx, req); err != nil {
		n.logger.Error("failed dispatching key manager status update to runtime",
			"err", err,
		)
		return err
	}

	n.logger.Debug("key manager status update dispatched")
	return nil
}

func (n *runtimeHostNotifier) updateKeyManagerPolicy(ctx context.Context, policy *keymanager.SignedPolicySGX) error {
	n.logger.Debug("got key manager policy update", "policy", policy)

	raw := cbor.Marshal(policy)
	req := &protocol.Body{RuntimeKeyManagerPolicyUpdateRequest: &protocol.RuntimeKeyManagerPolicyUpdateRequest{
		SignedPolicyRaw: raw,
	}}

	ctx, cancel := context.WithTimeout(ctx, notifyTimeout)
	defer cancel()

	if _, err := n.host.Call(ctx, req); err != nil {
		n.logger.Error("failed dispatching key manager policy update to runtime",
			"err", err,
		)
		return err
	}

	n.logger.Debug("key manager policy update dispatched")
	return nil
}

func (n *runtimeHostNotifier) updateKeyManagerQuotePolicy(ctx context.Context, policy *quote.Policy) error {
	n.logger.Debug("got key manager quote policy update", "policy", policy)

	req := &protocol.Body{RuntimeKeyManagerQuotePolicyUpdateRequest: &protocol.RuntimeKeyManagerQuotePolicyUpdateRequest{
		Policy: *policy,
	}}

	ctx, cancel := context.WithTimeout(ctx, notifyTimeout)
	defer cancel()

	if _, err := n.host.Call(ctx, req); err != nil {
		n.logger.Error("failed dispatching key manager quote policy update to runtime",
			"err", err,
		)
		return err
	}
	n.logger.Debug("key manager quote policy update dispatched")
	return nil
}

func (n *runtimeHostNotifier) watchConsensusLightBlocks() {
	rawCh, sub, err := n.consensus.WatchBlocks(n.ctx)
	if err != nil {
		n.logger.Error("failed to subscribe to consensus block updates",
			"err", err,
		)
		return
	}
	defer sub.Close()

	// Create a ring channel with a capacity of one as we only care about the latest block.
	blkCh := channels.NewRingChannel(channels.BufferCap(1))
	go func() {
		defer blkCh.Close()

		for blk := range rawCh {
			blkCh.In() <- blk
		}
	}()

	// Subscribe to runtime descriptor updates.
	dscCh, dscSub, err := n.runtime.WatchRegistryDescriptor()
	if err != nil {
		n.logger.Error("failed to subscribe to registry descriptor updates",
			"err", err,
		)
		return
	}
	defer dscSub.Close()

	n.logger.Debug("watching consensus layer blocks")

	var (
		maxAttestationAge           uint64
		lastAttestationUpdateHeight uint64
		lastAttestationUpdate       time.Time
	)
	for {
		select {
		case <-n.ctx.Done():
			n.logger.Debug("context canceled")
			return
		case <-n.stopCh:
			n.logger.Debug("termination requested")
			return
		case dsc := <-dscCh:
			// We only care about TEE-enabled runtimes.
			if dsc.TEEHardware != node.TEEHardwareIntelSGX {
				continue
			}

			var epoch beacon.EpochTime
			epoch, err = n.consensus.Beacon().GetEpoch(n.ctx, consensus.HeightLatest)
			if err != nil {
				n.logger.Error("failed to query current epoch",
					"err", err,
				)
				continue
			}

			// Fetch the active deployment.
			vi := dsc.ActiveDeployment(epoch)
			if vi == nil {
				continue
			}

			// Parse SGX constraints.
			var sc node.SGXConstraints
			if err = cbor.Unmarshal(vi.TEE, &sc); err != nil {
				n.logger.Error("malformed SGX constraints",
					"err", err,
				)
				continue
			}

			// Apply defaults.
			var params *registry.ConsensusParameters
			params, err = n.consensus.Registry().ConsensusParameters(n.ctx, consensus.HeightLatest)
			if err != nil {
				n.logger.Error("failed to query registry parameters",
					"err", err,
				)
				continue
			}
			if params.TEEFeatures != nil {
				params.TEEFeatures.SGX.ApplyDefaultConstraints(&sc)
			}

			// Pick a random interval between 50% and 90% of the MaxAttestationAge.
			if sc.MaxAttestationAge > 2 { // Ensure a is non-zero.
				a := (sc.MaxAttestationAge * 4) / 10 // 40%
				b := sc.MaxAttestationAge / 2        // 50%
				maxAttestationAge = b + uint64(rand.Int63n(int64(a)))
			} else {
				maxAttestationAge = 0 // Disarm height-based re-attestation.
			}
		case rawBlk, ok := <-blkCh.Out():
			// New consensus layer block.
			if !ok {
				return
			}
			blk := rawBlk.(*consensus.Block)
			height := uint64(blk.Height)

			// Notify the runtime that a new consensus layer block is available.
			ctx, cancel := context.WithTimeout(n.ctx, notifyTimeout)
			err = n.host.ConsensusSync(ctx, height)
			cancel()
			if err != nil {
				n.logger.Error("failed to notify runtime of a new consensus layer block",
					"err", err,
					"height", height,
				)
				continue
			}
			n.logger.Debug("runtime notified of new consensus layer block",
				"height", height,
			)

			// Assume runtime has already done the initial attestation.
			if lastAttestationUpdate.IsZero() {
				lastAttestationUpdateHeight = height
				lastAttestationUpdate = time.Now()
			}
			// Periodically trigger re-attestation.
			if maxAttestationAge > 0 && height-lastAttestationUpdateHeight > maxAttestationAge &&
				time.Since(lastAttestationUpdate) > minAttestationInterval {

				n.logger.Debug("requesting the runtime to update CapabilityTEE")

				n.host.UpdateCapabilityTEE()
				lastAttestationUpdateHeight = height
				lastAttestationUpdate = time.Now()
			}
		}
	}
}

// Implements protocol.Notifier.
func (n *runtimeHostNotifier) Start() error {
	n.Lock()
	defer n.Unlock()

	if n.started {
		return nil
	}
	n.started = true

	go n.watchPolicyUpdates()
	go n.watchConsensusLightBlocks()

	return nil
}

// Implements protocol.Notifier.
func (n *runtimeHostNotifier) Stop() {
	close(n.stopCh)
}

// NewRuntimeHostNotifier returns a protocol notifier that handles key manager policy updates.
func NewRuntimeHostNotifier(
	ctx context.Context,
	runtime Runtime,
	hostRt host.Runtime,
	consensus consensus.Backend,
) protocol.Notifier {
	return &runtimeHostNotifier{
		ctx:       ctx,
		stopCh:    make(chan struct{}),
		runtime:   runtime,
		host:      host.NewRichRuntime(hostRt),
		consensus: consensus,
		logger:    logging.GetLogger("runtime/registry/host"),
	}
}

// NewRuntimeHostHandler returns a protocol handler that provides the required host methods for the
// runtime to interact with the outside world.
//
// The passed identity may be nil.
func NewRuntimeHostHandler(
	env RuntimeHostHandlerEnvironment,
	runtime Runtime,
	consensus consensus.Backend,
) protocol.Handler {
	return &runtimeHostHandler{
		env:       env,
		runtime:   runtime,
		consensus: consensus,
	}
}
