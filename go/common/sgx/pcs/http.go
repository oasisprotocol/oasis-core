package pcs

import (
	"context"
	"crypto/x509"
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
)

//nolint:deadcode,varcheck
const (
	pcsAPISubscriptionKeyHeader = "Ocp-Apim-Subscription-Key"
	pcsAPITimeout               = 10 * time.Second
	pcsAPIBaseURL               = "https://api.trustedservices.intel.com/sgx"
	pcsAPIGetPCKCertificatePath = "/certification/v3/pckcert"
	pcsAPIGetRevocationListPath = "/certification/v3/pckcrl"
	pcsAPIGetTCBInfoPath        = "/certification/v3/tcb"
	pcsAPIGetQEIdentityPath     = "/certification/v3/qe/identity"
	pcsAPICertChainHeader       = "SGX-TCB-Info-Issuer-Chain"
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
		return nil, fmt.Errorf("pcs: response status error: %s", http.StatusText(resp.StatusCode))
	}

	return resp, nil
}

func (hc *httpClient) getUrl(p string) *url.URL { // nolint: revive
	u := *hc.baseURL
	u.Path = path.Join(u.Path, p)
	return &u
}

func (hc *httpClient) GetTCBBundle(ctx context.Context, fmspc []byte) (*TCBBundle, error) {
	// TODO: Cache based on FMSPC, with TTL that is less than expiration time.

	var tcbBundle TCBBundle

	// First fetch TCB info.
	u := hc.getUrl(pcsAPIGetTCBInfoPath)
	q := u.Query()
	q.Set("fmspc", hex.EncodeToString(fmspc))
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

	rawTCBInfo, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return nil, fmt.Errorf("pcs: failed to read TCB info response body: %w", err)
	}
	if err = json.Unmarshal(rawTCBInfo, &tcbBundle.TCBInfo); err != nil {
		return nil, fmt.Errorf("pcs: failed to parse TCB info: %w", err)
	}

	// Then fetch QE identity.
	u = hc.getUrl(pcsAPIGetQEIdentityPath)
	rsp, err = hc.doPCSRequest(ctx, u, http.MethodGet, "", nil, false)
	if err != nil {
		return nil, fmt.Errorf("pcs: QE identity request failed: %w", err)
	}
	defer rsp.Body.Close()

	rawQEIdentity, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return nil, fmt.Errorf("pcs: failed to read QE identity response body: %w", err)
	}
	if err = json.Unmarshal(rawQEIdentity, &tcbBundle.QEIdentity); err != nil {
		return nil, fmt.Errorf("pcs: failed to parse QE identity: %w", err)
	}

	return &tcbBundle, nil
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
