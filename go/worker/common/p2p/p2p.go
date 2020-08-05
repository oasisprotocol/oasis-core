// Package p2p implements the worker committee gossip network.
package p2p

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	core "github.com/libp2p/go-libp2p-core"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/transport"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr-net"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	registryAPI "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/configparser"
)

var allowUnroutableAddresses bool

// DebugForceallowUnroutableAddresses allows unroutable addresses.
func DebugForceAllowUnroutableAddresses() {
	allowUnroutableAddresses = true
}

// P2P is a peer-to-peer node using libp2p.
type P2P struct {
	sync.RWMutex
	*PeerManager

	ctx context.Context

	host   core.Host
	pubsub *pubsub.PubSub

	registerAddresses []multiaddr.Multiaddr
	topics            map[common.Namespace]*topicHandler

	logger *logging.Logger
}

// Addresses returns the P2P addresses of the node.
func (p *P2P) Addresses() []node.Address {
	if p == nil {
		return nil
	}

	var addrs []multiaddr.Multiaddr
	if len(p.registerAddresses) == 0 {
		addrs = p.host.Addrs()
	} else {
		addrs = p.registerAddresses
	}

	allowUnroutable := allowUnroutableAddresses

	var addresses []node.Address
	for _, v := range addrs {
		netAddr, err := manet.ToNetAddr(v)
		if err != nil {
			panic(err)
		}
		tcpAddr := (netAddr).(*net.TCPAddr)
		nodeAddr := node.Address{TCPAddr: *tcpAddr}
		if err := registryAPI.VerifyAddress(nodeAddr, allowUnroutable); err != nil {
			continue
		}

		addresses = append(addresses, nodeAddr)
	}

	return addresses
}

// Publish publishes a message to the gossip network.
func (p *P2P) Publish(ctx context.Context, runtimeID common.Namespace, msg *Message) {
	rawMsg := cbor.Marshal(msg)

	p.RLock()
	defer p.RUnlock()

	h := p.topics[runtimeID]
	if h == nil {
		p.logger.Error("attempted to publish message for unknown runtime ID",
			"runtime_id", runtimeID,
		)
		return
	}

	if err := h.topic.Publish(h.ctx, rawMsg); err != nil {
		h.logger.Error("failed to publish message to the network",
			"err", err,
		)
	}
}

// RegisterHandler registers a message handler for the specified runtime.
func (p *P2P) RegisterHandler(runtimeID common.Namespace, handler Handler) {
	p.Lock()
	defer p.Unlock()

	topicID, h, err := newTopicHandler(p, runtimeID, handler)
	if err != nil {
		panic(fmt.Sprintf("worker/common/p2p: failed to initialize topic handler: %s", err))
	}

	p.topics[runtimeID] = h
	_ = p.pubsub.RegisterTopicValidator(topicID, h.topicMessageValidator)
}

func (p *P2P) handleConnection(conn core.Conn) {
	if conn.Stat().Direction != network.DirInbound {
		return
	}

	var allowed bool
	defer func() {
		if !allowed {
			// Close connection if not allowed.
			p.logger.Error("closing connection from unauthorized peer",
				"peer_id", conn.RemotePeer(),
			)

			_ = conn.Close()
		}
	}()

	p.logger.Debug("new connection from peer",
		"peer_id", conn.RemotePeer(),
	)

	// Only allow nodes that should be part of the gossipsub network
	// to connect to us, regardless of handlers, on the hopes that
	// this increases responsiveness.
	//
	// Messages that we aren't interested in will be dropped without
	// much processing.
	allowed = p.isPeerAuthorized(conn.RemotePeer())
}

// New creates a new P2P node.
func New(ctx context.Context, identity *identity.Identity, consensus consensus.Backend) (*P2P, error) {
	// Instantiate the libp2p host.
	addresses, err := configparser.ParseAddressList(viper.GetStringSlice(cfgP2pAddresses))
	if err != nil {
		return nil, err
	}
	port := uint16(viper.GetInt(CfgP2pPort))

	var registerAddresses []multiaddr.Multiaddr
	for _, addr := range addresses {
		var mAddr multiaddr.Multiaddr
		mAddr, err = manet.FromNetAddr(&addr.TCPAddr)
		if err != nil {
			return nil, err
		}
		registerAddresses = append(registerAddresses, mAddr)
	}

	sourceMultiAddr, _ := multiaddr.NewMultiaddr(
		fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port),
	)

	// Oh hey, they finally got around to fixing the NAT traversal code,
	// so if people feel brave enough to want to interact with the
	// mountain of terrible uPNP/NAT-PMP implementations out there,
	// they can.
	host, err := libp2p.New(
		ctx,
		libp2p.ListenAddrs(sourceMultiAddr),
		libp2p.Identity(signerToPrivKey(identity.P2PSigner)),
	)
	if err != nil {
		return nil, fmt.Errorf("worker/common/p2p: failed to initialize libp2p host: %w", err)
	}

	// Initialize the gossipsub router.
	pubsub, err := pubsub.NewGossipSub(
		ctx,
		host,
		pubsub.WithMessageSigning(true),
		pubsub.WithStrictSignatureVerification(true),
		pubsub.WithFloodPublish(true),
	)
	if err != nil {
		return nil, fmt.Errorf("worker/common/p2p: failed to initialize libp2p gossipsub: %w", err)
	}

	p := &P2P{
		PeerManager:       newPeerManager(ctx, host, consensus),
		ctx:               ctx,
		host:              host,
		pubsub:            pubsub,
		registerAddresses: registerAddresses,
		topics:            make(map[common.Namespace]*topicHandler),
		logger:            logging.GetLogger("worker/common/p2p"),
	}
	p.host.Network().SetConnHandler(p.handleConnection)

	p.logger.Info("p2p host initialized",
		"address", fmt.Sprintf("%+v", host.Addrs()),
	)

	return p, nil
}

func runtimeIDToTopicID(runtimeID common.Namespace) string {
	return version.RuntimeCommitteeProtocol.String() + "/" + runtimeID.String()
}

func init() {
	// Make sure to decrease (global!) transport timeouts.
	transport.AcceptTimeout = 5 * time.Second
}
