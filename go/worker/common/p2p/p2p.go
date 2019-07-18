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
	"github.com/libp2p/go-libp2p-core/peerstore"
	"github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multiaddr-net"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/version"
	"github.com/oasislabs/ekiden/go/worker/common/configparser"
)

var protocolName = core.ProtocolID("/p2p/oasislabs.com/committee/" + version.CommitteeProtocol.String())

// Handler is a handler for P2P messages.
type Handler interface {
	// IsPeerAuthorized returns true if a given peer should be allowed
	// to send messages to us.
	IsPeerAuthorized(peerID []byte) bool

	// HandlePeerMessage handles an incoming message from a peer.
	HandlePeerMessage(peerID []byte, msg *Message) error
}

// P2P is a peer-to-peer node using libp2p.
type P2P struct {
	sync.RWMutex

	registerAddresses []multiaddr.Multiaddr

	host     core.Host
	handlers map[signature.MapKey]Handler

	logger *logging.Logger
}

func bytesToPeerID(raw []byte) (core.PeerID, error) {
	var id core.PeerID
	if err := id.Unmarshal(raw); err != nil {
		return "", err
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

	var addresses []node.Address
	for _, v := range addrs {
		netAddr, err := manet.ToNetAddr(v)
		if err != nil {
			panic(err)
		}
		tcpAddr := (netAddr).(*net.TCPAddr)
		addresses = append(addresses, node.Address{TCPAddr: *tcpAddr})
	}

	id, _ := p.host.ID().Marshal()

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
	peerID, err := bytesToPeerID(node.P2P.ID)
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
		_ = rawStream.Close()
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
	go func() {
		bctx := backoff.WithContext(backoff.NewExponentialBackOff(), ctx)

		err := backoff.Retry(func() error {
			return p.publishImpl(ctx, node, msg)
		}, bctx)
		if err != nil {
			p.logger.Warn("failed to publish message",
				"err", err,
				"node_id", node.ID,
			)
		}
	}()
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
		_ = stream.Close()
	}()

	peerID := stream.Conn().RemotePeer()
	rawPeerID, _ := peerID.Marshal()

	// Currently the protocol is very simple and only supports a single
	// request/response in a stream.
	var message Message
	if err := stream.Read(&message); err != nil {
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
	if !handler.IsPeerAuthorized(rawPeerID) {
		p.logger.Error("dropping stream from unauthorized peer",
			"runtime_id", message.RuntimeID,
			"peer_id", peerID,
		)

		_ = stream.Reset()
		return
	}

	err := handler.HandlePeerMessage(rawPeerID, &message)
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
	p.logger.Debug("new connection from peer",
		"peer_id", conn.RemotePeer(),
	)
}

// New creates a new P2P node.
func New(ctx context.Context, identity *identity.Identity) (*P2P, error) {
	addresses, err := configparser.ParseAddressList(viper.GetStringSlice(cfgP2pAddresses))
	if err != nil {
		return nil, err
	}
	port := uint16(viper.GetInt(cfgP2pPort))

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
