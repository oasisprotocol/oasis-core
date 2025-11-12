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
	consensus consensus.Backend

	logger *logging.Logger
}

func (s *service) HandleRequest(ctx context.Context, method string, body cbor.RawMessage) (any, error) {
	switch method {
	case MethodGetLightBlock:
		var height int64
		if err := cbor.Unmarshal(body, &height); err != nil {
			return nil, rpc.ErrBadRequest
		}
		return s.handleGetLightBlock(ctx, height)
	case MethodGetValidators:
		var height int64
		if err := cbor.Unmarshal(body, &height); err != nil {
			return nil, rpc.ErrBadRequest
		}
		return s.handleGetValidators(ctx, height)
	case MethodGetParameters:
		var height int64
		if err := cbor.Unmarshal(body, &height); err != nil {
			return nil, rpc.ErrBadRequest
		}
		return s.consensus.GetParameters(ctx, height)
	case MethodSubmitEvidence:
		var evidence consensus.Evidence
		if err := cbor.Unmarshal(body, &evidence); err != nil {
			return nil, rpc.ErrBadRequest
		}
		return nil, s.consensus.SubmitEvidence(ctx, &evidence)
	default:
		return nil, rpc.ErrMethodNotSupported
	}
}

func (s *service) handleGetLightBlock(ctx context.Context, height int64) (*consensus.LightBlock, error) {
	return s.consensus.GetLightBlock(ctx, height)
}

func (s *service) handleGetValidators(ctx context.Context, height int64) (*consensus.Validators, error) {
	return s.consensus.GetValidators(ctx, height)
}

// NewServer creates a new light block sync protocol server.
func NewServer(
	p2p rpc.P2P,
	chainContext string,
	consensus consensus.Backend,
) rpc.Server {
	p2p.RegisterProtocol(ProtocolID(chainContext), minProtocolPeers, totalProtocolPeers)

	return rpc.NewServer(
		ProtocolID(chainContext),
		&service{
			consensus: consensus,
			logger:    logging.GetLogger("consensus/p2p/light/server"),
		},
	)
}
