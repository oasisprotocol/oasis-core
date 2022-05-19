package pcs

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"time"
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
)

type httpClient struct {
	baseURL         *url.URL
	httpClient      *http.Client
	trustRoots      *x509.CertPool
	subscriptionKey string
}

func (hc *httpClient) GetTCBInfo(ctx context.Context, fmspc []byte) (*SignedTCBInfo, error) {
	return nil, fmt.Errorf("not yet implemented")
}

func (hc *httpClient) GetQEIdentity(ctx context.Context) (*SignedQEIdentity, error) {
	return nil, fmt.Errorf("not yet implemented")
}

// NewHTTPClient returns a new PCS HTTP endpoint.
func NewHTTPClient(cfg *Config) (Client, error) {
	hc := &httpClient{
		httpClient: &http.Client{
			Timeout: pcsAPITimeout,
		},
		subscriptionKey: cfg.SubscriptionKey,
		trustRoots:      IntelTrustRoots,
	}
	hc.baseURL, _ = url.Parse(pcsAPIBaseURL)

	return hc, nil
}
