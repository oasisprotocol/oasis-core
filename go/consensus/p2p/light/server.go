package light

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
)

const (
	// minProtocolPeers is the minimum number of peers from the registry we want to have connected
	// for the light blocks protocol.
	minProtocolPeers = 5

	// totalProtocolPeers is the number of peers we want to have connected for the light blocks protocol.
	totalProtocolPeers = 15
)

type service struct {
	consensus   consensus.Backend
	lightClient consensus.LightClient

	logger *logging.Logger
}

func (s *service) HandleRequest(ctx context.Context, method string, body cbor.RawMessage) (interface{}, error) {
	switch method {
	case MethodGetLightBlock:
		var rq int64
		if err := cbor.Unmarshal(body, &rq); err != nil {
			return nil, rpc.ErrBadRequest
		}
		return s.handleGetLightBlock(ctx, rq)
	case MethodGetParameters:
		var rq int64
		if err := cbor.Unmarshal(body, &rq); err != nil {
			return nil, rpc.ErrBadRequest
		}
		return s.consensus.GetParameters(ctx, rq)
	case MethodSubmitEvidence:
		var rq consensus.Evidence
		if err := cbor.Unmarshal(body, &rq); err != nil {
			return nil, rpc.ErrBadRequest
		}
		return nil, s.consensus.SubmitEvidence(ctx, &rq)
	default:
		return nil, rpc.ErrMethodNotSupported
	}
}

func (s *service) handleGetLightBlock(ctx context.Context, height int64) (*consensus.LightBlock, error) {
	lb, err := s.consensus.GetLightBlock(ctx, height)
	if err != nil {
		// Also try the local light store.
		if lb, err = s.lightClient.TrustedLightBlock(height); err != nil {
			return nil, err
		}
	}
	return lb, nil
}

// NewServer creates a new light block sync protocol server.
func NewServer(
	p2p rpc.P2P,
	chainContext string,
	consensus consensus.Backend,
	lightClient consensus.LightClient,
) rpc.Server {
	p2p.RegisterProtocol(ProtocolID(chainContext), minProtocolPeers, totalProtocolPeers)

	return rpc.NewServer(
		ProtocolID(chainContext),
		&service{
			consensus:   consensus,
			lightClient: lightClient,
			logger:      logging.GetLogger("consensus/p2p/light/server"),
		},
	)
}
