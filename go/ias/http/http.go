// Package http implements the HTTP IAS endpoint.
package http

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"time"

	"golang.org/x/net/context/ctxhttp"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	"github.com/oasisprotocol/oasis-core/go/ias/api"
)

var (
	logger = logging.GetLogger("ias/http")

	_ api.Endpoint = (*httpEndpoint)(nil)
	_ api.Endpoint = (*mockEndpoint)(nil)
)

const (
	// iasAPISubscriptionKeyHeader is the header IAS V4 endpoint uses for client
	// authentication.
	iasAPISubscriptionKeyHeader = "Ocp-Apim-Subscription-Key"
	iasAPITimeout               = 10 * time.Second
	iasAPIProductionBaseURL     = "https://api.trustedservices.intel.com/sgx"
	iasAPITestingBaseURL        = "https://api.trustedservices.intel.com/sgx/dev"
	iasAPIAttestationReportPath = "/attestation/v4/report"
	iasAPISigRLPath             = "/attestation/v4/sigrl/"
)

type httpEndpoint struct {
	baseURL         *url.URL
	httpClient      *http.Client
	trustRoots      *x509.CertPool
	subscriptionKey string

	spidInfo api.SPIDInfo
}

func (e *httpEndpoint) doIASRequest(ctx context.Context, method, uPath, bodyType string, body io.Reader) (*http.Response, error) {
	u := *e.baseURL
	u.Path = path.Join(u.Path, uPath)

	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", bodyType)
	}
	req.Header.Set(iasAPISubscriptionKeyHeader, e.subscriptionKey)

	resp, err := ctxhttp.Do(ctx, e.httpClient, req)
	if err != nil {
		logger.Error("ias request error", "err", err, "method", method, "url", u)
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		logger.Error("ias response status error", "status", http.StatusText(resp.StatusCode), "method", method, "url", u)
		return nil, fmt.Errorf("ias: response status error: %s", http.StatusText(resp.StatusCode))
	}

	return resp, nil
}

func (e *httpEndpoint) VerifyEvidence(ctx context.Context, evidence *api.Evidence) (*ias.AVRBundle, error) {
	// Validate arguments.
	//
	// XXX: Should this happen here, or should the caller handle this?
	var quote ias.Quote
	if err := quote.UnmarshalBinary(evidence.Quote); err != nil {
		return nil, fmt.Errorf("ias: invalid quoteBinary: %w", err)
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
		return nil, fmt.Errorf("ias: failed to marshal: %w", err)
	}

	// Dispatch the request via HTTP.
	resp, err := e.doIASRequest(ctx, http.MethodPost, iasAPIAttestationReportPath, "application/json", bytes.NewReader(reqPayload))
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("ias: http POST failed: %w", err)
	}
	defer resp.Body.Close()

	// Extract the pertinent parts of the response.
	sig := []byte(resp.Header.Get("X-IASReport-Signature"))
	certChain := []byte(resp.Header.Get("X-IASReport-Signing-Certificate"))
	avr, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ias: failed to read response body: %w", err)
	}

	// Ensure that the AVR is valid.
	if _, err = ias.DecodeAVR(avr, sig, certChain, e.trustRoots, time.Now()); err != nil {
		return nil, fmt.Errorf("ias: failed to parse/validate AVR: %w", err)
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
	p := path.Join(iasAPISigRLPath, hex.EncodeToString(gid[:]))
	resp, err := e.doIASRequest(ctx, http.MethodGet, p, "", nil)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("ias: http GET failed: %w", err)
	}

	// Extract and parse the SigRL.
	sigRL, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ias: failed to read response body: %w", err)
	}
	var b []byte
	if len(sigRL) > 0 { // No SigRL is signified by a 0 byte response.
		if b, err = base64.StdEncoding.DecodeString(string(sigRL)); err != nil {
			return nil, fmt.Errorf("ias: failed to decode SigRL: %w", err)
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
		return nil, fmt.Errorf("ias: failed to generate mock AVR: %w", err)
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
	// SubscriptionKey is the IAS API key used for client authentication.
	SubscriptionKey string

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

	if !cfg.IsProduction {
		logger.Warn("IsProduction not set, enclaves in debug mode will be allowed")
		ias.SetAllowDebugEnclaves()
	}
	if cfg.DebugIsMock {
		logger.Warn("DebugSkipVerify set, VerifyEvidence calls will be mocked")
		ias.SetSkipVerify() // Intel isn't signing anything.
		return &mockEndpoint{
			spidInfo: api.SPIDInfo{
				SPID:               spidBin,
				QuoteSignatureType: cfg.QuoteSignatureType,
			},
		}, nil
	}

	e := &httpEndpoint{
		httpClient: &http.Client{
			Timeout: iasAPITimeout,
		},
		subscriptionKey: cfg.SubscriptionKey,
		trustRoots:      ias.IntelTrustRoots,
		spidInfo: api.SPIDInfo{
			SPID:               spidBin,
			QuoteSignatureType: cfg.QuoteSignatureType,
		},
	}
	if cfg.IsProduction {
		e.baseURL, _ = url.Parse(iasAPIProductionBaseURL)
	} else {
		e.baseURL, _ = url.Parse(iasAPITestingBaseURL)
	}

	return e, nil
}
