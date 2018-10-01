package ias

import (
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	//commonPB "github.com/oasislabs/ekiden/go/grpc/common"
	pb "github.com/oasislabs/ekiden/go/grpc/ias"
)

var (
	_ pb.IASServer = (*grpcServer)(nil)

	evidenceSignatureContext = []byte("EkIASEvi")
)

type signedEvidence struct {
	signature.Signed
}

func (s *signedEvidence) Open(context []byte, evidence *evidence) error { // nolint: interfacer
	return s.Signed.Open(context, evidence)
}

type evidence struct {
	Quote       []byte `codec:"quote"`
	PSEManifest []byte `codec:"pse_manifest"`
}

func (e *evidence) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, e)
}

type grpcServer struct {
	endpoint Endpoint
}

func (s *grpcServer) VerifyEvidence(ctx context.Context, req *pb.VerifyEvidenceRequest) (*pb.VerifyEvidenceResponse, error) {
	var signed signedEvidence
	if err := signed.FromProto(req.GetEvidence()); err != nil {
		return nil, err
	}

	var ev evidence
	if err := signed.Open(evidenceSignatureContext, &ev); err != nil {
		return nil, err
	}

	// TODO: Authenticate/validate the verification request.
	//  * signed.Signature.PublicKey MUST be in the entity registry.
	//  * ev.Quote MUST be well-formed and for an approved MRENCLAVE.
	//  * (Possibly other validation things here.)

	// XXX: Do something with the nonce?
	avr, sig, certChain, err := s.endpoint.VerifyEvidence(ctx, ev.Quote, ev.PSEManifest, "")
	if err != nil {
		return nil, err
	}

	var resp pb.VerifyEvidenceResponse
	resp.Avr = avr
	resp.Signature = sig
	resp.CertificateChain = certChain

	return &resp, nil
}

// NewGRPCServer initializes and registers a new gRPC IAS server backed
// by the provided backend (Endpoint).
func NewGRPCServer(srv *grpc.Server, endpoint Endpoint) {
	s := &grpcServer{
		endpoint: endpoint,
	}
	pb.RegisterIASServer(srv, s)
}
