// Package ias implements the IAS proxy client.
package ias

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	tlsCert "github.com/oasislabs/ekiden/go/common/crypto/tls"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/sgx/ias"
	iasGrpc "github.com/oasislabs/ekiden/go/grpc/ias"
)

const (
	cfgProxyAddress    = "ias.proxy_addr"
	cfgTLSCertFile     = "ias.tls"
	cfgDebugSkipVerify = "ias.debug.skip_verify"
)

// Flags has our flags.
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

// GetSPID returns the SPID associated with the IAS proxy.
func (s *IAS) GetSPID(ctx context.Context) (ias.SPID, error) {
	return s.spidInfo.SPID, nil
}

// GetQuoteSignatureType returns the quote signature type associated with the SPID.
func (s *IAS) GetQuoteSignatureType(ctx context.Context) (*ias.SignatureType, error) {
	return &s.spidInfo.QuoteSignatureType, nil
}

// VerifyEvidence verifies attestation evidence.
func (s *IAS) VerifyEvidence(ctx context.Context, runtimeID signature.PublicKey, quote, pseManifest []byte, nonce string) (avr, sig, chain []byte, err error) {
	if s.client == nil {
		// If the IAS proxy is not configured, generate a mock AVR, under the
		// assumption that the runtime is built to support this.  The runtime
		// with reject the mock AVR if it is not.
		avr, err = ias.NewMockAVR(quote, nonce)
		if err != nil {
			return nil, nil, nil, err
		}
	} else {
		// Ensure the quote passes basic sanity/security checks before even
		// bothering to contact the backend.
		var untrustedQuote *ias.Quote
		untrustedQuote, err = ias.DecodeQuote(quote)
		if err != nil {
			return nil, nil, nil, err
		}
		if err = untrustedQuote.Verify(); err != nil {
			return nil, nil, nil, err
		}

		evidence := ias.Evidence{
			ID:          runtimeID,
			Quote:       quote,
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
		resp, err = s.client.VerifyEvidence(ctx, &req)
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
	proxyAddr := viper.GetString(cfgProxyAddress)

	s := &IAS{
		identity: identity,
		logger:   logging.GetLogger("ias"),
	}

	if proxyAddr == "" {
		s.logger.Warn("IAS proxy is not configured, all reports will be mocked")

		s.spidInfo = &ias.SPIDInfo{}
		_ = s.spidInfo.SPID.UnmarshalBinary(make([]byte, ias.SPIDSize))
	} else {
		tlsCertFile := viper.GetString(cfgTLSCertFile)
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

	if viper.GetBool(cfgDebugSkipVerify) {
		s.logger.Warn("`ias.debug.skip_verify` set, AVR signature validation bypassed")
		ias.SetSkipVerify()
	}

	return s, nil
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().AddFlagSet(Flags)
	}
}

func init() {
	Flags.String(cfgProxyAddress, "", "IAS proxy address")
	Flags.String(cfgTLSCertFile, "", "IAS proxy TLS certificate")
	Flags.Bool(cfgDebugSkipVerify, false, "skip IAS AVR signature verification (UNSAFE)")

	_ = viper.BindPFlags(Flags)
}
