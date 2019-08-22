package ias

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/net/context/ctxhttp"

	"github.com/oasislabs/ekiden/go/common/json"
	"github.com/oasislabs/ekiden/go/common/logging"
)

var (
	// ErrMalformedSPID is the error returned when an SPID is malformed.
	ErrMalformedSPID = errors.New("ias: malformed SPID")

	logger = logging.GetLogger("common/ias")

	_ encoding.BinaryMarshaler   = (*SPID)(nil)
	_ encoding.BinaryUnmarshaler = (*SPID)(nil)
)

// SPIDSize is the size of SPID.
const SPIDSize = 16

// SPID is an SPID.
type SPID [SPIDSize]byte

// String returns a string representation of the SPID.
func (s SPID) String() string {
	return hex.EncodeToString(s[:])
}

// MarshalBinary encodes an SPID into binary form.
func (s SPID) MarshalBinary() (data []byte, err error) {
	data = append([]byte{}, s[:]...)
	return
}

// UnmarshalBinary decodes a binary marshaled SPID.
func (s *SPID) UnmarshalBinary(data []byte) error {
	if len(data) != SPIDSize {
		return ErrMalformedSPID
	}

	copy((*s)[:], data)

	return nil
}

// SPIDInfo contains information about the SPID associated with the client certificate.
type SPIDInfo struct {
	SPID               SPID
	QuoteSignatureType SignatureType
}

// Endpoint is an attestation validation endpoint, likely remote.
type Endpoint interface {
	// VerifyEvidence takes the provided quote, (optional) PSE manifest, and
	// (optional) nonce, and returns the corresponding AVR, signature, and
	// ceritficate chain respectively.
	VerifyEvidence(ctx context.Context, quote, pseManifest []byte, nonce string) ([]byte, []byte, []byte, error)

	// GetSPID returns the SPID and associated info used by the endpoint.
	GetSPIDInfo(ctx context.Context) (*SPIDInfo, error)

	// GetSigRL returns the Signature Revocation List for a given EPID group.
	GetSigRL(ctx context.Context, epidGID uint32) ([]byte, error)
}

type httpEndpoint struct {
	baseURL    *url.URL
	httpClient *http.Client
	trustRoots *x509.CertPool

	spidInfo SPIDInfo
}

func (e *httpEndpoint) VerifyEvidence(ctx context.Context, quote, pseManifest []byte, nonce string) ([]byte, []byte, []byte, error) {
	// Validate arguments.
	//
	// XXX: Should this happen here, or should the caller handle this?
	if _, err := DecodeQuote(quote); err != nil {
		return nil, nil, nil, errors.Wrap(err, "ias: invalid quote")
	}
	if len(nonce) > nonceMaxLen {
		return nil, nil, nil, fmt.Errorf("ias: invalid nonce length")
	}

	// Encode the payload in the format that IAS wants.
	reqPayload := json.Marshal(&iasEvidencePayload{
		ISVEnclaveQuote: quote,
		PSEManifest:     pseManifest,
		Nonce:           nonce,
	})

	// Dispatch the request via HTTP.
	u := *e.baseURL
	u.Path = path.Join(u.Path, "/attestation/sgx/v3/report")
	resp, err := ctxhttp.Post(ctx, e.httpClient, u.String(), "application/json", bytes.NewReader(reqPayload))
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "ias: http POST failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, nil, errors.Wrapf(err, "ias: http POST returned error: %s", http.StatusText(resp.StatusCode))
	}

	// Extract the pertinent parts of the response.
	sig := []byte(resp.Header.Get("X-IASReport-Signature"))
	certChain := []byte(resp.Header.Get("X-IASReport-Signing-Certificate"))
	avr, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "ias: failed to read response body")
	}

	// Ensure that the AVR is valid.
	if _, err = DecodeAVR(avr, sig, certChain, e.trustRoots, time.Now()); err != nil {
		return nil, nil, nil, errors.Wrap(err, "ias: failed to parse/validate AVR")
	}

	// Check for advisories.
	// TODO: Maybe forward these to the caller.
	if advisoryIDs := resp.Header.Get("Advisory-IDs"); advisoryIDs != "" {
		logger.Warn("Received advisory IDs", "advisoryIDs", advisoryIDs)
	}
	if advisoryURL := resp.Header.Get("Advisory-URL"); advisoryURL != "" {
		logger.Warn("Received advisory URL", "advisoryURL", advisoryURL)
	}

	return avr, sig, certChain, nil
}

func (e *httpEndpoint) GetSPIDInfo(ctx context.Context) (*SPIDInfo, error) {
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

type iasEvidencePayload struct {
	ISVEnclaveQuote []byte `codec:"isvEnclaveQuote"`
	PSEManifest     []byte `codec:"pseManifest,omitempty"`
	Nonce           string `codec:"string,omitempty"`
}

// NewIASEndpoint returns a new Endpoint backed by an IAS server operated
// by Intel.
func NewIASEndpoint(
	authCertFile string,
	authKeyFile string,
	authCertCA *x509.Certificate,
	spid string,
	quoteSignatureType SignatureType,
	isProduction bool,
) (Endpoint, error) {
	tlsRoots, err := x509.SystemCertPool()
	if err != nil {
		return nil, errors.Wrap(err, "ias: failed to load system cert pool")
	}

	authCert, err := tls.LoadX509KeyPair(authCertFile, authKeyFile)
	if err != nil {
		return nil, errors.Wrap(err, "ias: failed to load client certificate")
	}
	authCert.Leaf, err = x509.ParseCertificate(authCert.Certificate[0])
	if err != nil {
		return nil, errors.Wrap(err, "ias: failed to parse client leaf certificate")
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{authCert},
		RootCAs:      tlsRoots,
	}

	// Go's TLS library requires that client certificates be signed with
	// a cert in the pool that's passed to the TLS client, that also is
	// used to verify the server cert.
	mustRevalidate := true
	if authCertCA != nil {
		// The caller provided a CA for the authentication cert.
		tlsRoots.AddCert(authCertCA)
	} else if _, err = authCert.Leaf.Verify(x509.VerifyOptions{Roots: tlsRoots}); err != nil {
		if _, ok := err.(x509.UnknownAuthorityError); !ok {
			// Should never happen.
			return nil, errors.Wrap(err, "ias: failed to validate client certificate")
		}

		// The cert is presumably self-signed.
		tlsRoots.AddCert(authCert.Leaf)
	} else {
		// Cert is signed by a CA.
		mustRevalidate = false
	}
	if mustRevalidate {
		// Ensure that the the client authentication certificate is now
		// actually signed by a cert in the TLS client cert pool.
		if _, err = authCert.Leaf.Verify(x509.VerifyOptions{Roots: tlsRoots}); err != nil {
			return nil, errors.Wrap(err, "ias: failed to verify client certificate CA")
		}
	}

	switch quoteSignatureType {
	case SignatureUnlinkable, SignatureLinkable:
	default:
		return nil, fmt.Errorf("ias: invalid signature type: %04x", quoteSignatureType)
	}

	spidFromHex, err := hex.DecodeString(spid)
	if err != nil {
		return nil, ErrMalformedSPID
	}
	var spidBin SPID
	if err := spidBin.UnmarshalBinary(spidFromHex); err != nil {
		return nil, err
	}

	e := &httpEndpoint{
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
		trustRoots: IntelTrustRoots,
		spidInfo: SPIDInfo{
			SPID:               spidBin,
			QuoteSignatureType: quoteSignatureType,
		},
	}
	if isProduction {
		e.baseURL, _ = url.Parse("https://as.sgx.trustedservices.intel.com/")
	} else {
		e.baseURL, _ = url.Parse("https://test-as.sgx.trustedservices.intel.com/")
	}

	return e, nil
}
