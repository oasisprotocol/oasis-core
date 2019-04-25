package ias

import (
	"context"

	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	pb "github.com/oasislabs/ekiden/go/grpc/ias"
)

var (
	_ pb.IASServer = (*grpcServer)(nil)

	_ cbor.Marshaler   = (*Evidence)(nil)
	_ cbor.Unmarshaler = (*Evidence)(nil)
	_ cbor.Marshaler   = (*SignedEvidence)(nil)
	_ cbor.Unmarshaler = (*SignedEvidence)(nil)

	// EvidenceSignatureContext is the signature context used for verifying evidence.
	EvidenceSignatureContext = []byte("EkIASEvi")
)

// SignedEvidence is signed evidence.
type SignedEvidence struct {
	signature.Signed
}

// Open first verifies the blob signature and then unmarshals the blob.
func (s *SignedEvidence) Open(context []byte, evidence *Evidence) error { // nolint: interfacer
	return s.Signed.Open(context, evidence)
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (s *SignedEvidence) MarshalCBOR() []byte {
	return s.Signed.MarshalCBOR()
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (s *SignedEvidence) UnmarshalCBOR(data []byte) error {
	return s.Signed.UnmarshalCBOR(data)
}

// Evidence is attestation evidence.
type Evidence struct {
	Quote       []byte `codec:"quote"`
	PSEManifest []byte `codec:"pse_manifest"`
	Nonce       string `codec:"nonce"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (e Evidence) MarshalCBOR() []byte {
	return cbor.Marshal(e)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (e *Evidence) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, e)
}

type grpcServer struct {
	endpoint Endpoint
}

func (s *grpcServer) VerifyEvidence(ctx context.Context, req *pb.VerifyEvidenceRequest) (*pb.VerifyEvidenceResponse, error) {
	var signed SignedEvidence
	if err := signed.FromProto(req.GetEvidence()); err != nil {
		return nil, err
	}

	var ev Evidence
	if err := signed.Open(EvidenceSignatureContext, &ev); err != nil {
		return nil, err
	}

	// TODO: Authenticate/validate the verification request.
	//  * signed.Signature.PublicKey MUST be in the entity registry.
	//  * ev.Quote MUST be well-formed and for an approved MRENCLAVE.
	//  * (Possibly other validation things here.)

	avr, sig, certChain, err := s.endpoint.VerifyEvidence(ctx, ev.Quote, ev.PSEManifest, ev.Nonce)
	if err != nil {
		return nil, err
	}

	var resp pb.VerifyEvidenceResponse
	resp.Avr = avr
	resp.Signature = sig
	resp.CertificateChain = certChain

	return &resp, nil
}

func (s *grpcServer) GetSPIDInfo(ctx context.Context, req *pb.GetSPIDInfoRequest) (*pb.GetSPIDInfoResponse, error) {
	info, err := s.endpoint.GetSPIDInfo(ctx)
	if err != nil {
		return nil, err
	}

	spid, err := info.SPID.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &pb.GetSPIDInfoResponse{
		Spid:               spid,
		QuoteSignatureType: uint32(info.QuoteSignatureType),
	}, nil
}

func (s *grpcServer) GetSigRL(ctx context.Context, req *pb.GetSigRLRequest) (*pb.GetSigRLResponse, error) {
	// TODO: Validate the EPID group ID.

	sigRL, err := s.endpoint.GetSigRL(ctx, req.GetEpidGid())
	if err != nil {
		return nil, err
	}

	return &pb.GetSigRLResponse{
		SigRl: sigRL,
	}, nil
}

// NewGRPCServer initializes and registers a new gRPC IAS server backed
// by the provided backend (Endpoint).
func NewGRPCServer(srv *grpc.Server, endpoint Endpoint) {
	s := &grpcServer{
		endpoint: endpoint,
	}
	pb.RegisterIASServer(srv, s)
}
