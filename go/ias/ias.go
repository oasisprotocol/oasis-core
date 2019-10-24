// Package ias implements the IAS proxy client.
package ias

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	tlsCert "github.com/oasislabs/oasis-core/go/common/crypto/tls"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/sgx/ias"
	iasGrpc "github.com/oasislabs/oasis-core/go/grpc/ias"
)

const (
	CfgProxyAddress       = "ias.proxy_addr"
	CfgTLSCertFile        = "ias.tls"
	CfgDebugSkipVerify    = "ias.debug.skip_verify"
	CfgAllowDebugEnclaves = "ias.debug.allow_debug_enclaves"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// IAS is an IAS proxy client.
type IAS struct {
	identity *identity.Identity

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

func (s *IAS) fetchSPIDInfo(ctx context.Context) error {
	if s.spidInfo != nil || s.client == nil {
		return nil
	}

	// Request SPID info from the proxy.
	info, err := s.client.GetSPIDInfo(ctx, &iasGrpc.GetSPIDInfoRequest{}, grpc.WaitForReady(true))
	if err != nil {
		return err
	}

	spidInfo := &ias.SPIDInfo{
		QuoteSignatureType: ias.SignatureType(info.QuoteSignatureType),
	}
	if err := spidInfo.SPID.UnmarshalBinary(info.Spid); err != nil {
		return err
	}

	s.spidInfo = spidInfo
	return nil
}

// GetSPID returns the SPID associated with the IAS proxy.
func (s *IAS) GetSPID(ctx context.Context) (ias.SPID, error) {
	if err := s.fetchSPIDInfo(ctx); err != nil {
		return ias.SPID{}, err
	}
	return s.spidInfo.SPID, nil
}

// GetQuoteSignatureType returns the quote signature type associated with the SPID.
func (s *IAS) GetQuoteSignatureType(ctx context.Context) (*ias.SignatureType, error) {
	if err := s.fetchSPIDInfo(ctx); err != nil {
		return nil, err
	}
	return &s.spidInfo.QuoteSignatureType, nil
}

// VerifyEvidence verifies attestation evidence.
func (s *IAS) VerifyEvidence(ctx context.Context, runtimeID signature.PublicKey, quoteBinary, pseManifest []byte, nonce string) (avr, sig, chain []byte, err error) {
	if s.client == nil {
		// If the IAS proxy is not configured, generate a mock AVR, under the
		// assumption that the runtime is built to support this.  The runtime
		// with reject the mock AVR if it is not.
		avr, err = ias.NewMockAVR(quoteBinary, nonce)
		if err != nil {
			return nil, nil, nil, err
		}
	} else {
		// Ensure the quoteBinary passes basic sanity/security checks before even
		// bothering to contact the backend.
		var untrustedQuote ias.Quote
		err = untrustedQuote.UnmarshalBinary(quoteBinary)
		if err != nil {
			return nil, nil, nil, err
		}
		if err = untrustedQuote.Verify(); err != nil {
			return nil, nil, nil, err
		}

		evidence := ias.Evidence{
			ID:          runtimeID,
			Quote:       quoteBinary,
			PSEManifest: pseManifest,
			Nonce:       nonce,
		}
		var signedEvidence *signature.Signed
		signedEvidence, err = signature.SignSigned(s.identity.NodeSigner, ias.EvidenceSignatureContext, &evidence)
		if err != nil {
			return
		}

		req := iasGrpc.VerifyEvidenceRequest{
			Evidence: signedEvidence.ToProto(),
		}
		var resp *iasGrpc.VerifyEvidenceResponse
		resp, err = s.client.VerifyEvidence(ctx, &req, grpc.WaitForReady(true))
		if err != nil {
			return
		}

		avr = resp.Avr
		sig = resp.Signature
		chain = resp.CertificateChain
	}

	sig = cbor.FixSliceForSerde(sig)
	chain = cbor.FixSliceForSerde(chain)

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
func New(identity *identity.Identity) (*IAS, error) {
	proxyAddr := viper.GetString(CfgProxyAddress)

	s := &IAS{
		identity: identity,
		logger:   logging.GetLogger("ias"),
	}

	if proxyAddr == "" {
		s.logger.Warn("IAS proxy is not configured, all reports will be mocked")

		s.spidInfo = &ias.SPIDInfo{}
		_ = s.spidInfo.SPID.UnmarshalBinary(make([]byte, ias.SPIDSize))
	} else {
		tlsCertFile := viper.GetString(CfgTLSCertFile)
		if tlsCertFile == "" {
			s.logger.Error("IAS proxy TLS certificate not configured")
			return nil, errors.New("ias: proxy TLS certificate not configured")
		}

		proxyCert, err := tlsCert.LoadCertificate(tlsCertFile)
		if err != nil {
			return nil, err
		}

		parsedCert, err := x509.ParseCertificate(proxyCert.Certificate[0])
		if err != nil {
			return nil, err
		}

		certPool := x509.NewCertPool()
		certPool.AddCert(parsedCert)
		creds := credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{*identity.TLSCertificate},
			RootCAs:      certPool,
			ServerName:   ias.CommonName,
		})

		conn, err := grpc.Dial(proxyAddr, grpc.WithTransportCredentials(creds))
		if err != nil {
			return nil, err
		}
		s.conn = conn
		s.client = iasGrpc.NewIASClient(conn)
	}

	if viper.GetBool(CfgDebugSkipVerify) {
		s.logger.Warn("`ias.debug.skip_verify` set, AVR signature validation bypassed")
		ias.SetSkipVerify()
	}

	if viper.GetBool(CfgAllowDebugEnclaves) {
		s.logger.Warn("`ias.debug.allow_debug_enclaves` set, enclaves in debug mode will be allowed")
		ias.SetAllowDebugEnclaves()
	}

	return s, nil
}

func init() {
	Flags.String(CfgProxyAddress, "", "IAS proxy address")
	Flags.String(CfgTLSCertFile, "", "IAS proxy TLS certificate")
	Flags.Bool(CfgDebugSkipVerify, false, "skip IAS AVR signature verification (UNSAFE)")
	Flags.Bool(CfgAllowDebugEnclaves, false, "allow enclaves compiled in debug mode (UNSAFE)")

	_ = Flags.MarkHidden(CfgAllowDebugEnclaves)

	_ = viper.BindPFlags(Flags)
}
