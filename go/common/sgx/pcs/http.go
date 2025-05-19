package pcs

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"

	"golang.org/x/net/context/ctxhttp"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
)

//nolint:deadcode,varcheck
const (
	pcsAPISubscriptionKeyHeader              = "Ocp-Apim-Subscription-Key"
	pcsAPITimeout                            = 10 * time.Second
	pcsAPIBaseURL                            = "https://api.trustedservices.intel.com"
	pcsAPIGetPCKCertificatePath              = "/sgx/certification/v4/pckcert"
	pcsAPIGetRevocationListPath              = "/sgx/certification/v4/pckcrl"
	pcsAPIGetSgxTCBInfoPath                  = "/sgx/certification/v4/tcb"
	pcsAPIGetTdxTCBInfoPath                  = "/tdx/certification/v4/tcb"
	pcsAPIGetSgxQEIdentityPath               = "/sgx/certification/v4/qe/identity"
	pcsAPIGetTdxQEIdentityPath               = "/tdx/certification/v4/qe/identity"
	pcsAPIGetSgxTCBEvaluationDataNumbersPath = "/sgx/certification/v4/tcbevaluationdatanumbers"
	pcsAPIGetTdxTCBEvaluationDataNumbersPath = "/tdx/certification/v4/tcbevaluationdatanumbers"
	pcsAPICertChainHeader                    = "TCB-Info-Issuer-Chain"
	pcsAPIPCKIIssuerChainHeader              = "SGX-PCK-Certificate-Issuer-Chain"
)

// HTTPClientConfig is the Intel SGX PCS client configuration.
type HTTPClientConfig struct {
	// SubscriptionKey is the Intel PCS API key used for client authentication (needed for PCK
	// certificate retrieval).
	SubscriptionKey string
}

type httpClient struct {
	baseURL         *url.URL
	httpClient      *http.Client
	trustRoots      *x509.CertPool
	subscriptionKey string

	logger *logging.Logger
}

func (hc *httpClient) doPCSRequest(ctx context.Context, u *url.URL, method, bodyType string, body io.Reader, needsAuth bool) (*http.Response, error) {
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", bodyType)
	}
	if needsAuth {
		req.Header.Set(pcsAPISubscriptionKeyHeader, hc.subscriptionKey)
	}

	resp, err := ctxhttp.Do(ctx, hc.httpClient, req)
	if err != nil {
		hc.logger.Error("PCS request error",
			"err", err,
			"method", method,
			"url", u,
		)
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		hc.logger.Error("PCS response status error",
			"status", http.StatusText(resp.StatusCode),
			"method", method,
			"url", u,
		)
		resp.Body.Close()
		return nil, fmt.Errorf("pcs: response status error: %s", http.StatusText(resp.StatusCode))
	}

	return resp, nil
}

func (hc *httpClient) getUrl(p string) *url.URL { // nolint: revive
	u := *hc.baseURL
	u.Path = path.Join(u.Path, p)
	return &u
}

func (hc *httpClient) GetTCBBundle(ctx context.Context, teeType TeeType, fmspc []byte, tcbEvaluationDataNumber uint32) (*TCBBundle, error) {
	var (
		tcbBundle               TCBBundle
		pcsAPIGetTCBInfoPath    string
		pcsAPIGetQEIdentityPath string
	)
	switch teeType {
	case TeeTypeSGX:
		pcsAPIGetTCBInfoPath = pcsAPIGetSgxTCBInfoPath
		pcsAPIGetQEIdentityPath = pcsAPIGetSgxQEIdentityPath
	case TeeTypeTDX:
		pcsAPIGetTCBInfoPath = pcsAPIGetTdxTCBInfoPath
		pcsAPIGetQEIdentityPath = pcsAPIGetTdxQEIdentityPath
	default:
		return nil, fmt.Errorf("pcs: unsupported TEE type: %s", teeType)
	}

	// First fetch TCB info.
	u := hc.getUrl(pcsAPIGetTCBInfoPath)
	q := u.Query()
	q.Set("fmspc", hex.EncodeToString(fmspc))
	q.Set("tcbEvaluationDataNumber", strconv.FormatUint(uint64(tcbEvaluationDataNumber), 10))
	u.RawQuery = q.Encode()
	rsp, err := hc.doPCSRequest(ctx, u, http.MethodGet, "", nil, false)
	if err != nil {
		return nil, fmt.Errorf("pcs: TCB info request failed: %w", err)
	}
	defer rsp.Body.Close()

	rawCerts, err := url.QueryUnescape(rsp.Header.Get(pcsAPICertChainHeader))
	if err != nil {
		return nil, fmt.Errorf("pcs: failed to parse TCB info cert chain header: %w", err)
	}
	tcbBundle.Certificates = []byte(rawCerts)

	rawTCBInfo, err := io.ReadAll(rsp.Body)
	if err != nil {
		return nil, fmt.Errorf("pcs: failed to read TCB info response body: %w", err)
	}
	if err = json.Unmarshal(rawTCBInfo, &tcbBundle.TCBInfo); err != nil {
		return nil, fmt.Errorf("pcs: failed to parse TCB info: %w", err)
	}

	// Then fetch QE identity.
	u = hc.getUrl(pcsAPIGetQEIdentityPath)
	q = u.Query()
	q.Set("tcbEvaluationDataNumber", strconv.FormatUint(uint64(tcbEvaluationDataNumber), 10))
	u.RawQuery = q.Encode()
	rsp, err = hc.doPCSRequest(ctx, u, http.MethodGet, "", nil, false)
	if err != nil {
		return nil, fmt.Errorf("pcs: QE identity request failed: %w", err)
	}
	defer rsp.Body.Close()

	rawQEIdentity, err := io.ReadAll(rsp.Body)
	if err != nil {
		return nil, fmt.Errorf("pcs: failed to read QE identity response body: %w", err)
	}
	if err = json.Unmarshal(rawQEIdentity, &tcbBundle.QEIdentity); err != nil {
		return nil, fmt.Errorf("pcs: failed to parse QE identity: %w", err)
	}

	return &tcbBundle, nil
}

func (hc *httpClient) GetTCBEvaluationDataNumbers(ctx context.Context, teeType TeeType) ([]uint32, error) {
	var pcsAPIGetTCBEvaluationDataNumbersPath string
	switch teeType {
	case TeeTypeSGX:
		pcsAPIGetTCBEvaluationDataNumbersPath = pcsAPIGetSgxTCBEvaluationDataNumbersPath
	case TeeTypeTDX:
		pcsAPIGetTCBEvaluationDataNumbersPath = pcsAPIGetTdxTCBEvaluationDataNumbersPath
	default:
		return nil, fmt.Errorf("pcs: unsupported TEE type: %s", teeType)
	}

	u := hc.getUrl(pcsAPIGetTCBEvaluationDataNumbersPath)
	rsp, err := hc.doPCSRequest(ctx, u, http.MethodGet, "", nil, false)
	if err != nil {
		return nil, fmt.Errorf("pcs: TCB evaluation data numbers request failed: %w", err)
	}
	defer rsp.Body.Close()

	raw, err := io.ReadAll(rsp.Body)
	if err != nil {
		return nil, fmt.Errorf("pcs: failed to read TCB evaluation data numbers response body: %w", err)
	}
	var tcbEvalDataNums SignedTCBEvaluationDataNumbers
	if err = json.Unmarshal(raw, &tcbEvalDataNums); err != nil {
		return nil, fmt.Errorf("pcs: failed to parse TCB evaluation data numbers: %w", err)
	}

	numbers := make([]uint32, 0, len(tcbEvalDataNums.Numbers.EvaluationDataNumbers))
	for _, edn := range tcbEvalDataNums.Numbers.EvaluationDataNumbers {
		numbers = append(numbers, edn.EvaluationDataNumber)
	}
	return numbers, nil
}

func (hc *httpClient) GetPCKCertificateChain(ctx context.Context, platformData []byte, encPpid [384]byte, cpusvn [16]byte, pcesvn uint16, pceid uint16) ([]*x509.Certificate, error) {
	u := hc.getUrl(pcsAPIGetPCKCertificatePath)
	q := u.Query()

	// Base16-encoded PCESVN value (2 bytes, little endian).
	var pcesvnBytes [2]byte
	binary.LittleEndian.PutUint16(pcesvnBytes[:], pcesvn)

	// Base16-encoded PCE-ID value (2 bytes, little endian)
	var pceidBytes [2]byte
	binary.LittleEndian.PutUint16(pceidBytes[:], pceid)

	var rsp *http.Response
	var err error
	switch {
	case platformData == nil:
		// Use GET endpoint with encrypted PPID.
		q.Set("encrypted_ppid", hex.EncodeToString(encPpid[:]))
		q.Set("cpusvn", hex.EncodeToString(cpusvn[:]))
		q.Set("pcesvn", hex.EncodeToString(pcesvnBytes[:]))
		q.Set("pceid", hex.EncodeToString(pceidBytes[:]))
		u.RawQuery = q.Encode()
		rsp, err = hc.doPCSRequest(ctx, u, http.MethodGet, "", nil, false) // nolint: bodyclose
	default:
		// Platform data is provided, use the POST endpoint with platform data.
		payload, merr := json.Marshal(&struct {
			PlatformManifest string `json:"platformManifest"`
			CPUSVN           string `json:"cpusvn"`
			PCESVN           string `json:"pcesvn"`
			PCEID            string `json:"pceid"`
		}{
			PlatformManifest: hex.EncodeToString(platformData),
			CPUSVN:           hex.EncodeToString(cpusvn[:]),
			PCESVN:           hex.EncodeToString(pcesvnBytes[:]),
			PCEID:            hex.EncodeToString(pceidBytes[:]),
		})
		if merr != nil {
			return nil, fmt.Errorf("pcs: failed to marshal PCK certificate request payload: %w", merr)
		}
		rsp, err = hc.doPCSRequest(ctx, u, http.MethodPost, "application/json", bytes.NewReader(payload), false) // nolint: bodyclose
	}
	if err != nil {
		return nil, fmt.Errorf("pcs: PCK certificate request failed: %w", err)
	}
	defer rsp.Body.Close()

	// Parse issuer Certificate chain for SGX PCK Certificate.
	rawCerts, err := url.QueryUnescape(rsp.Header.Get(pcsAPIPCKIIssuerChainHeader))
	if err != nil {
		return nil, fmt.Errorf("pcs: failed to parse PCK certificate issuer chain header: %w", err)
	}
	// It consists of SGX Root CA Certificate and SGX Intermediate CA Certificate.
	intermediateCert, rest, err := CertFromPEM([]byte(rawCerts))
	if err != nil {
		return nil, fmt.Errorf("pcs: failed to parse SGX Intermediate CA Certificate from PCK certificate issuer chain: %w", err)
	}
	rootCert, _, err := CertFromPEM(rest)
	if err != nil {
		return nil, fmt.Errorf("pcs: failed to parse root SGX Root CA Certificate from PCK certificate issuer chain: %w", err)
	}

	// Parse PCK Certificate.
	rawPCKCert, err := io.ReadAll(rsp.Body)
	if err != nil {
		return nil, fmt.Errorf("pcs: failed to read PCK certificate response body: %w", err)
	}
	leafCert, _, err := CertFromPEM(rawPCKCert)
	if err != nil {
		return nil, fmt.Errorf("pcs: failed to parse PCK certificate: %w", err)
	}

	return []*x509.Certificate{leafCert, intermediateCert, rootCert}, nil
}

// NewHTTPClient returns a new PCS HTTP endpoint.
func NewHTTPClient(cfg *HTTPClientConfig) (Client, error) {
	hc := &httpClient{
		httpClient: &http.Client{
			Timeout: pcsAPITimeout,
		},
		subscriptionKey: cfg.SubscriptionKey,
		trustRoots:      IntelTrustRoots,
		logger:          logging.GetLogger("common/sgx/pcs/http"),
	}
	hc.baseURL, _ = url.Parse(pcsAPIBaseURL)

	return hc, nil
}
