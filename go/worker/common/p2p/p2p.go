package p2p

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/cenkalti/backoff"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core"
	"github.com/libp2p/go-libp2p-core/helpers"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/peerstore"
	"github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multiaddr-net"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/version"
	registry "github.com/oasislabs/oasis-core/go/registry"
	registryAPI "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/worker/common/configparser"
)

var (
	protocolName = core.ProtocolID("/p2p/oasislabs.com/committee/" + version.CommitteeProtocol.String())

	forceAllowUnroutableAddresses bool
)

// DebugForceAllowUnroutableAddresses exists entirely for the benefit
// of the byzantine node, which doesn't use viper properly to configure
// various subcomponent behavior.
func DebugForceAllowUnroutableAddresses() {
	forceAllowUnroutableAddresses = true
}

// Handler is a handler for P2P messages.
type Handler interface {
	// IsPeerAuthorized returns true if a given peer should be allowed
	// to send messages to us.
	IsPeerAuthorized(peerID signature.PublicKey) bool

	// HandlePeerMessage handles an incoming message from a peer.
	HandlePeerMessage(peerID signature.PublicKey, msg *Message) error
}

// P2P is a peer-to-peer node using libp2p.
type P2P struct {
	sync.RWMutex
	publishing sync.WaitGroup

	registerAddresses []multiaddr.Multiaddr

	host     core.Host
	handlers map[signature.MapKey]Handler

	logger *logging.Logger
}

func publicKeyToPeerID(pk signature.PublicKey) (core.PeerID, error) {
	pubKey, err := publicKeyToPubKey(pk)
	if err != nil {
		return "", err
	}

	id, err := peer.IDFromPublicKey(pubKey)
	if err != nil {
		return "", err
	}

	return id, nil
}

func peerIDToPublicKey(peerID core.PeerID) (signature.PublicKey, error) {
	pk, err := peerID.ExtractPublicKey()
	if err != nil {
		return nil, err
	}
	id, err := pubKeyToPublicKey(pk)
	if err != nil {
		return nil, err
	}

	return id, nil
}

// Info returns the information needed to establish connections to this
// node via the P2P transport.
func (p *P2P) Info() node.P2PInfo {
	var addrs []multiaddr.Multiaddr
	if len(p.registerAddresses) == 0 {
		addrs = p.host.Addrs()
	} else {
		addrs = p.registerAddresses
	}

	allowUnroutable := viper.GetBool(registry.CfgDebugAllowUnroutableAddresses)
	if forceAllowUnroutableAddresses {
		allowUnroutable = forceAllowUnroutableAddresses
	}

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

	id, err := peerIDToPublicKey(p.host.ID())
	if err != nil {
		panic(err)
	}

	return node.P2PInfo{
		ID:        id,
		Addresses: addresses,
	}
}

func (p *P2P) addPeerInfo(peerID core.PeerID, addresses []node.Address) error {
	if addresses == nil {
		return errors.New("nil address list")
	}

	var addrs []multiaddr.Multiaddr
	for _, nodeAddr := range addresses {
		mAddr, err := manet.FromNetAddr(&nodeAddr.TCPAddr)
		if err != nil {
			return err
		}

		addrs = append(addrs, mAddr)
	}

	ps := p.host.Peerstore()
	ps.ClearAddrs(peerID)
	ps.AddAddrs(peerID, addrs, peerstore.RecentlyConnectedAddrTTL)

	return nil
}

func (p *P2P) publishImpl(ctx context.Context, node *node.Node, msg *Message) error {
	peerID, err := publicKeyToPeerID(node.P2P.ID)
	if err != nil {
		return backoff.Permanent(err)
	}

	// Update peer address.
	if perr := p.addPeerInfo(peerID, node.P2P.Addresses); perr != nil {
		p.logger.Error("failed to update peer address",
			"err", perr,
			"node_id", node.ID,
		)
		return backoff.Permanent(perr)
	}

	rawStream, err := p.host.NewStream(ctx, peerID, protocolName)
	if err != nil {
		return err
	}
	defer func() {
		_ = helpers.FullClose(rawStream)
	}()

	stream := NewStream(rawStream)
	if err := stream.Write(msg); err != nil {
		return err
	}

	var response Message
	if err := stream.Read(&response); err != nil {
		return err
	}

	if response.Error != nil {
		return errors.New(response.Error.Message)
	} else if response.Ack != nil {
		return nil
	} else {
		return errors.New("invalid response to publish")
	}
}

// Publish publishes a message to the destination node.
//
// If message publish fails, it is automatically retried until successful,
// using an exponential backoff.
func (p *P2P) Publish(ctx context.Context, node *node.Node, msg *Message) {
	p.publishing.Add(1)
	go func() {
		defer p.publishing.Done()
		bctx := backoff.WithContext(backoff.NewExponentialBackOff(), ctx)

		err := backoff.Retry(func() error {
			p.logger.Debug("publishing message",
				"node_id", node.ID,
			)
			perr := p.publishImpl(ctx, node, msg)
			if perr != nil {
				p.logger.Warn("failed to publish message",
					"err", perr,
					"node_id", node.ID,
				)
			}
			return perr
		}, bctx)
		if err != nil {
			p.logger.Warn("failed to publish message, not retrying",
				"err", err,
				"node_id", node.ID,
			)
			return
		}
		p.logger.Debug("successfully published message",
			"node_id", node.ID,
		)
	}()
}

// Wait until Publish routines have finished.
func (p *P2P) Flush() {
	p.publishing.Wait()
}

// RegisterHandler registeres a message handler for the specified runtime.
func (p *P2P) RegisterHandler(runtimeID signature.PublicKey, handler Handler) {
	p.Lock()
	p.handlers[runtimeID.ToMapKey()] = handler
	p.Unlock()

	p.logger.Debug("registered handler",
		"runtime_id", runtimeID,
	)
}

func (p *P2P) handleStreamMessages(stream *Stream) {
	defer func() {
		_ = helpers.FullClose(stream.Stream)
	}()

	peerID := stream.Conn().RemotePeer()
	p.logger.Debug("new message from peer",
		"peer_id", peerID,
	)
	id, err := peerIDToPublicKey(peerID)
	if err != nil {
		p.logger.Error("error while extracting public key from peer ID",
			"err", err,
			"peer_id", peerID,
		)
		return
	}

	// Currently the protocol is very simple and only supports a single
	// request/response in a stream.
	var message Message
	if err = stream.Read(&message); err != nil {
		p.logger.Error("error while receiving message from peer",
			"err", err,
			"peer_id", peerID,
		)
		return
	}

	// Determine handler based on the runtime identifier.
	p.RLock()
	handler, ok := p.handlers[message.RuntimeID.ToMapKey()]
	p.RUnlock()
	if !ok {
		p.logger.Error("received message for unknown runtime",
			"runtime_id", message.RuntimeID,
			"peer_id", peerID,
		)
		return
	}

	// Check if peer is authorized to send messages.
	if !handler.IsPeerAuthorized(id) {
		p.logger.Error("dropping stream from unauthorized peer",
			"runtime_id", message.RuntimeID,
			"peer_id", peerID,
		)
		return
	}

	err = handler.HandlePeerMessage(id, &message)
	response := &Message{
		RuntimeID:    message.RuntimeID,
		GroupVersion: message.GroupVersion,
		SpanContext:  nil,
	}
	if err == nil {
		response.Ack = &Ack{}
	} else {
		response.Error = &Error{Message: err.Error()}
	}

	_ = stream.Write(response)
}

func (p *P2P) handleStream(rawStream core.Stream) {
	stream := NewStream(rawStream)
	go p.handleStreamMessages(stream)
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

	id, err := peerIDToPublicKey(conn.RemotePeer())
	if err != nil {
		p.logger.Error("error while extracting public key from peer ID",
			"err", err,
			"peer_id", conn.RemotePeer(),
		)
		return
	}

	// Make sure that connection is allowed by at least one handler.
	p.RLock()
	defer p.RUnlock()

	for _, handler := range p.handlers {
		if handler.IsPeerAuthorized(id) {
			allowed = true
			return
		}
	}
}

// New creates a new P2P node.
func New(ctx context.Context, identity *identity.Identity) (*P2P, error) {
	addresses, err := configparser.ParseAddressList(viper.GetStringSlice(cfgP2pAddresses))
	if err != nil {
		return nil, err
	}
	port := uint16(viper.GetInt(CfgP2pPort))

	p2pKey := signerToPrivKey(identity.P2PSigner)

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

	// NOTE: Do not initialize NAT functionality as the implementation that
	//       libp2p currently uses for gateway/default route discovery is
	//       done badly -- it requires parsing outputs of various CLI binaries
	//       instead of doing it properly via syscalls/NETLINK.
	//
	//       The dependency chain for the used implementation is:
	//       - https://github.com/libp2p/go-libp2p-nat
	//       - https://github.com/fd/go-nat
	//       - https://github.com/jackpal/gateway (the problematic library)
	//
	//       If we ever decide that we need NAT functionality we should consider
	//       switching the implementation with something like:
	//       - https://gitweb.torproject.org/tor-fw-helper.git/tree/natclient
	host, err := libp2p.New(
		ctx,
		libp2p.ListenAddrs(sourceMultiAddr),
		libp2p.Identity(p2pKey),
	)
	if err != nil {
		return nil, err
	}

	p := &P2P{
		registerAddresses: registerAddresses,
		host:              host,
		handlers:          make(map[signature.MapKey]Handler),
		logger:            logging.GetLogger("worker/common/p2p"),
	}

	p.host.Network().SetConnHandler(p.handleConnection)
	p.host.SetStreamHandler(protocolName, p.handleStream)

	p.logger.Info("p2p host initialized",
		"address", fmt.Sprintf("%+v", host.Addrs()),
	)

	return p, nil
}
