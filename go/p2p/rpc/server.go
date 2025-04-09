package rpc

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
)

const (
	RequestHandleTimeout  = 60 * time.Second
	ResponseWriteDeadline = 60 * time.Second
)

// Service is an RPC service implementation.
type Service interface {
	// HandleRequest handles an incoming RPC request.
	HandleRequest(ctx context.Context, method string, body cbor.RawMessage) (any, error)
}

// Server is an RPC server for the given protocol.
type Server interface {
	// Protocol returns the unique protocol identifier.
	Protocol() protocol.ID

	// HandleStream handles an incoming stream.
	HandleStream(stream network.Stream)
}

type server struct {
	Service

	protocolID protocol.ID

	logger *logging.Logger
}

func (s *server) Protocol() protocol.ID {
	return s.protocolID
}

func (s *server) HandleStream(stream network.Stream) {
	defer stream.Close()

	logger := s.logger.With("peer_id", stream.Conn().RemotePeer())
	codec := cbor.NewMessageCodec(stream, codecModuleName)

	// Read request.
	var request Request
	_ = stream.SetReadDeadline(time.Now().Add(RequestReadDeadline))
	if err := codec.Read(&request); err != nil {
		logger.Debug("failed to read request",
			"err", err,
		)
		return
	}
	_ = stream.SetReadDeadline(time.Time{})

	logger.Debug("received request",
		"method", request.Method,
	)

	// Get peer's addr info.
	addr := peer.AddrInfo{
		ID:    stream.Conn().RemotePeer(),
		Addrs: []core.Multiaddr{stream.Conn().RemoteMultiaddr()},
	}

	// Handle request.
	ctx, cancel := context.WithTimeout(context.Background(), RequestHandleTimeout)
	ctx = WithPeerAddrInfo(ctx, addr)
	rsp, err := s.HandleRequest(ctx, request.Method, request.Body)
	cancel()

	// Generate response.
	var response Response
	switch err {
	case nil:
		response.Ok = cbor.Marshal(rsp)
	default:
		logger.Debug("failed to process request",
			"err", err,
			"method", request.Method,
		)

		module, code := errors.Code(err)
		response.Error = &Error{
			Module:  module,
			Code:    code,
			Message: err.Error(),
		}
	}

	// Send response.
	_ = stream.SetWriteDeadline(time.Now().Add(ResponseWriteDeadline))
	if err = codec.Write(&response); err != nil {
		logger.Debug("failed to write response",
			"err", err,
		)
		return
	}
	_ = stream.SetWriteDeadline(time.Time{})
}

// NewServer creates a new RPC server for the given protocol.
func NewServer(protocolID protocol.ID, srv Service) Server {
	return &server{
		Service:    srv,
		protocolID: protocolID,
		logger:     logging.GetLogger("p2p/rpc/server").With("protocol", protocolID),
	}
}
