// Package ias implements the IAS proxy client.
package ias

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/ias"
	"github.com/oasislabs/ekiden/go/common/logging"
	iasGrpc "github.com/oasislabs/ekiden/go/grpc/ias"
)

// IAS is an IAS proxy client.
type IAS struct {
	identity *signature.PrivateKey

	conn   *grpc.ClientConn
	client iasGrpc.IASClient

	spidInfo *ias.SPIDInfo

	logger *logging.Logger
}

// Close the connection.
func (s *IAS) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}

	return nil
}

// GetSPID returns the SPID associated with the IAS proxy.
func (s *IAS) GetSPID(ctx context.Context) (ias.SPID, error) {
	return s.spidInfo.SPID, nil
}

// GetQuoteSignatureType returns the quote signature type associated with the SPID.
func (s *IAS) GetQuoteSignatureType(ctx context.Context) (*ias.SignatureType, error) {
	return &s.spidInfo.QuoteSignatureType, nil
}

// VerifyEvidence verifies attestation evidence.
func (s *IAS) VerifyEvidence(ctx context.Context, quote, pseManifest []byte) (avr, sig, chain []byte, err error) {
	if s.client == nil {
		// Generate mock AVR when IAS is not configured. Signature and certificate chain are empty
		// and such a report will not pass any verification so it can only be used with verification
		// disabled (e.g., built with EKIDEN_UNSAFE_SKIP_AVR_VERIFY=1).
		avr = []byte(
			fmt.Sprintf(
				"{\"isvEnclaveQuoteStatus\": \"OK\", \"isvEnclaveQuoteBody\": \"%s\"}",
				base64.StdEncoding.EncodeToString(quote),
			),
		)
		sig = []byte("")
		chain = []byte("")
		return
	}

	evidence := ias.Evidence{
		Quote:       quote,
		PSEManifest: pseManifest,
	}
	se, err := signature.SignSigned(*s.identity, ias.EvidenceSignatureContext, &evidence)
	if err != nil {
		return
	}

	req := iasGrpc.VerifyEvidenceRequest{
		Evidence: se.ToProto(),
	}
	res, err := s.client.VerifyEvidence(ctx, &req)
	if err != nil {
		return
	}

	avr = res.Avr
	sig = res.Signature
	chain = res.CertificateChain
	return
}

// GetSigRL returns the Signature Revocation List associated with the given
// SPID group.
func (s *IAS) GetSigRL(ctx context.Context, epidGID uint32) ([]byte, error) {
	if s.client == nil {
		// If the client is not configured, return a empty SigRL.
		return nil, nil
	}

	req := iasGrpc.GetSigRLRequest{
		EpidGid: epidGID,
	}
	res, err := s.client.GetSigRL(ctx, &req)
	if err != nil {
		return nil, err
	}

	return res.SigRl, nil
}

// New creates a new IAS client instance.
func New(identity *signature.PrivateKey, proxyAddr string) (*IAS, error) {
	s := &IAS{
		identity: identity,
		logger:   logging.GetLogger("worker/ias"),
	}

	if proxyAddr == "" {
		s.logger.Warn("IAS proxy is not configured, all reports will be mocked")

		s.spidInfo = &ias.SPIDInfo{}
	} else {
		conn, err := grpc.Dial(proxyAddr, grpc.WithInsecure()) // TODO: TLS?
		if err != nil {
			return nil, err
		}
		s.conn = conn
		s.client = iasGrpc.NewIASClient(conn)

		// Request SPID info from the proxy.
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		info, err := s.client.GetSPIDInfo(ctx, &iasGrpc.GetSPIDInfoRequest{})
		if err != nil {
			return nil, err
		}

		s.spidInfo = &ias.SPIDInfo{
			QuoteSignatureType: ias.SignatureType(info.QuoteSignatureType),
		}
		if err := s.spidInfo.SPID.UnmarshalBinary(info.Spid); err != nil {
			return nil, err
		}
	}

	return s, nil
}
