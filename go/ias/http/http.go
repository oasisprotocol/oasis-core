// Package http implements the HTTP IAS endpoint.
package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/net/context/ctxhttp"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/sgx/ias"
	"github.com/oasislabs/oasis-core/go/ias/api"
)

var (
	logger = logging.GetLogger("ias/http")

	_ api.Endpoint = (*httpEndpoint)(nil)
	_ api.Endpoint = (*mockEndpoint)(nil)
)

type httpEndpoint struct {
	baseURL    *url.URL
	httpClient *http.Client
	trustRoots *x509.CertPool

	spidInfo api.SPIDInfo
}

func (e *httpEndpoint) VerifyEvidence(ctx context.Context, evidence *api.Evidence) (*ias.AVRBundle, error) {
	// Validate arguments.
	//
	// XXX: Should this happen here, or should the caller handle this?
	var quote ias.Quote
	if err := quote.UnmarshalBinary(evidence.Quote); err != nil {
		return nil, errors.Wrap(err, "ias: invalid quoteBinary")
	}
	if len(evidence.Nonce) > ias.NonceMaxLen {
		return nil, fmt.Errorf("ias: invalid nonce length")
	}

	if err := quote.Verify(); err != nil {
		return nil, err
	}

	// Encode the payload in the format that IAS wants.
	reqPayload, err := json.Marshal(&iasEvidencePayload{
		ISVEnclaveQuote: evidence.Quote,
		PSEManifest:     evidence.PSEManifest,
		Nonce:           evidence.Nonce,
	})
	if err != nil {
		return nil, errors.Wrap(err, "ias: failed to marshal")
	}

	// Dispatch the request via HTTP.
	u := *e.baseURL
	u.Path = path.Join(u.Path, "/attestation/sgx/v3/report")
	resp, err := ctxhttp.Post(ctx, e.httpClient, u.String(), "application/json", bytes.NewReader(reqPayload))
	if err != nil {
		return nil, errors.Wrap(err, "ias: http POST failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Wrapf(err, "ias: http POST returned error: %s", http.StatusText(resp.StatusCode))
	}

	// Extract the pertinent parts of the response.
	sig := []byte(resp.Header.Get("X-IASReport-Signature"))
	certChain := []byte(resp.Header.Get("X-IASReport-Signing-Certificate"))
	avr, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "ias: failed to read response body")
	}

	// Ensure that the AVR is valid.
	if _, err = ias.DecodeAVR(avr, sig, certChain, e.trustRoots, time.Now()); err != nil {
		return nil, errors.Wrap(err, "ias: failed to parse/validate AVR")
	}

	// Check for advisories.
	// TODO: Maybe forward these to the caller.
	if advisoryIDs := resp.Header.Get("Advisory-IDs"); advisoryIDs != "" {
		logger.Warn("Received advisory IDs", "advisoryIDs", advisoryIDs)
	}
	if advisoryURL := resp.Header.Get("Advisory-URL"); advisoryURL != "" {
		logger.Warn("Received advisory URL", "advisoryURL", advisoryURL)
	}

	return &ias.AVRBundle{
		Body:             avr,
		Signature:        sig,
		CertificateChain: certChain,
	}, nil
}

func (e *httpEndpoint) GetSPIDInfo(ctx context.Context) (*api.SPIDInfo, error) {
	return &e.spidInfo, nil
}

func (e *httpEndpoint) GetSigRL(ctx context.Context, epidGID uint32) ([]byte, error) {
	var gid [4]byte
	binary.BigEndian.PutUint32(gid[:], epidGID)

	// Dispatch the request via HTTP.
	u := *e.baseURL
	u.Path = path.Join(u.Path, "/attestation/sgx/v3/sigrl/"+hex.EncodeToString(gid[:]))
	resp, err := ctxhttp.Get(ctx, e.httpClient, u.String())
	if err != nil {
		return nil, errors.Wrap(err, "ias: http GET failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Wrapf(err, "ias: http GET returned error: %s", http.StatusText(resp.StatusCode))
	}

	// Extract and parse the SigRL.
	sigRL, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "ias: failed to read response body")
	}
	var b []byte
	if len(sigRL) > 0 { // No SigRL is signified by a 0 byte response.
		if b, err = base64.StdEncoding.DecodeString(string(sigRL)); err != nil {
			return nil, errors.Wrap(err, "ias: failed to decode SigRL")
		}
	}

	return b, nil
}

func (e *httpEndpoint) Cleanup() {
}

type iasEvidencePayload struct {
	ISVEnclaveQuote []byte `json:"isvEnclaveQuote"`
	PSEManifest     []byte `json:"pseManifest,omitempty"`
	Nonce           string `json:"nonce,omitempty"`
}

type mockEndpoint struct {
	spidInfo api.SPIDInfo
}

func (e *mockEndpoint) VerifyEvidence(ctx context.Context, evidence *api.Evidence) (*ias.AVRBundle, error) {
	if len(evidence.Nonce) > ias.NonceMaxLen {
		return nil, fmt.Errorf("ias: invalid nonce length")
	}

	avr, err := ias.NewMockAVR(evidence.Quote, evidence.Nonce)
	if err != nil {
		return nil, errors.Wrap(err, "ias: failed to generate mock AVR")
	}

	return &ias.AVRBundle{
		Body: avr,
	}, nil
}

func (e *mockEndpoint) GetSPIDInfo(ctx context.Context) (*api.SPIDInfo, error) {
	return &e.spidInfo, nil
}

func (e *mockEndpoint) GetSigRL(ctx context.Context, epidGID uint32) ([]byte, error) {
	return nil, nil
}

func (e *mockEndpoint) Cleanup() {
}

// Config is the IAS HTTP endpoint configuration.
type Config struct {
	// AuthCert is the IAS authentication certificate (and private key).
	AuthCert *tls.Certificate

	// AuthCertCA is the CA cert for the IAS authentication certificate.
	AuthCertCA *x509.Certificate

	// SPID is the service provider ID.
	SPID string

	// QuoteSignatureType is the IAS signature quote type.
	QuoteSignatureType ias.SignatureType

	// IsProduction specifies if the endpoint should connect to the
	// production endpoint.
	IsProduction bool

	// DebugIsMock is set if set to true will return mock AVR responses
	// and not actually contact IAS.
	DebugIsMock bool
}

// New returns a new IAS HTTP endpoint.
func New(cfg *Config) (api.Endpoint, error) {
	spidFromHex, err := hex.DecodeString(cfg.SPID)
	if err != nil {
		return nil, ias.ErrMalformedSPID
	}
	var spidBin ias.SPID
	if err = spidBin.UnmarshalBinary(spidFromHex); err != nil {
		return nil, err
	}

	if cfg.DebugIsMock {
		logger.Warn("DebugSkipVerify set, VerifyEvidence calls will be mocked")

		ias.SetSkipVerify()         // Intel isn't signing anything.
		ias.SetAllowDebugEnclaves() // Debug enclaves are used for testing.
		return &mockEndpoint{
			spidInfo: api.SPIDInfo{
				SPID:               spidBin,
				QuoteSignatureType: cfg.QuoteSignatureType,
			},
		}, nil
	}

	tlsRoots, err := x509.SystemCertPool()
	if err != nil {
		return nil, errors.Wrap(err, "ias: failed to load system cert pool")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cfg.AuthCert},
		RootCAs:      tlsRoots,
	}

	// Go's TLS library requires that client certificates be signed with
	// a cert in the pool that's passed to the TLS client, that also is
	// used to verify the server cert.
	mustRevalidate := true
	if cfg.AuthCertCA != nil {
		// The caller provided a CA for the authentication cert.
		tlsRoots.AddCert(cfg.AuthCertCA)
	} else if _, err = cfg.AuthCert.Leaf.Verify(x509.VerifyOptions{Roots: tlsRoots}); err != nil {
		if _, ok := err.(x509.UnknownAuthorityError); !ok {
			// Should never happen.
			return nil, errors.Wrap(err, "ias: failed to validate client certificate")
		}

		// The cert is presumably self-signed.
		tlsRoots.AddCert(cfg.AuthCert.Leaf)
	} else {
		// Cert is signed by a CA.
		mustRevalidate = false
	}
	if mustRevalidate {
		// Ensure that the the client authentication certificate is now
		// actually signed by a cert in the TLS client cert pool.
		if _, err = cfg.AuthCert.Leaf.Verify(x509.VerifyOptions{Roots: tlsRoots}); err != nil {
			return nil, errors.Wrap(err, "ias: failed to verify client certificate CA")
		}
	}

	e := &httpEndpoint{
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
		trustRoots: ias.IntelTrustRoots,
		spidInfo: api.SPIDInfo{
			SPID:               spidBin,
			QuoteSignatureType: cfg.QuoteSignatureType,
		},
	}
	if cfg.IsProduction {
		e.baseURL, _ = url.Parse("https://as.sgx.trustedservices.intel.com/")
	} else {
		e.baseURL, _ = url.Parse("https://test-as.sgx.trustedservices.intel.com/")
	}

	return e, nil
}
