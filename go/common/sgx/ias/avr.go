// Package ias provides routines for interacting with the Intel Attestation
// Service.
package ias

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/sgx"
)

// NonceMaxLen is the maximum length of the AVR nonce.
const NonceMaxLen = 32

// requiredAVRVersion is the required AV report version.
const requiredAVRVersion = 4

var (
	unsafeSkipVerify         bool
	unsafeAllowDebugEnclaves bool
)

// TimestampFormat is the format of the AVR timestamp, suitable for use with
// time.Parse.
//
// Workaround for https://github.com/golang/go/issues/21990
const TimestampFormat = "2006-01-02T15:04:05.999999999"

var (
	isvQuoteFwdMap = map[string]ISVEnclaveQuoteStatus{
		"OK":                                    QuoteOK,
		"SIGNATURE_INVALID":                     QuoteSignatureInvalid,
		"GROUP_REVOKED":                         QuoteGroupRevoked,
		"SIGNATURE_REVOKED":                     QuoteSignatureRevoked,
		"KEY_REVOKED":                           QuoteKeyRevoked,
		"SIGRL_VERSION_MISMATCH":                QuoteSigRLVersionMismatch,
		"GROUP_OUT_OF_DATE":                     QuoteGroupOutOfDate,
		"CONFIGURATION_NEEDED":                  QuoteConfigurationNeeded,
		"SW_HARDENING_NEEDED":                   QuoteSwHardeningNeeded,
		"CONFIGURATION_AND_SW_HARDENING_NEEDED": QuoteConfigurationAndSwHardeningNeeded,
	}
	isvQuoteRevMap = make(map[ISVEnclaveQuoteStatus]string)

	pseManifFwdMap = map[string]PSEManifestStatus{
		"OK":                  ManifestOK,
		"UNKNOWN":             ManifestUnknown,
		"INVALID":             ManifestInvalid,
		"OUT_OF_DATE":         ManifestOutOfDate,
		"REVOKED":             ManifestRevoked,
		"RL_VERSION_MISMATCH": ManifestRLVersionMismatch,
	}
	pseManifRevMap = make(map[PSEManifestStatus]string)

	crlReasonRevMap = map[CRLReason]string{
		ReasonUnspecified:          "unspecified",
		ReasonKeyCompromise:        "keyCompromise",
		ReasonCACompromise:         "cACompromise",
		ReasonAffiliationChanged:   "affiliationChanged",
		ReasonSuperseded:           "superseded",
		ReasonCessationOfOperation: "cessationOfOperation",
		ReasonCertificateHold:      "certificateHold",
		ReasonRemoveFromCRL:        "removeFromCRL",
		ReasonPrivilegeWithdrawn:   "privilegeWithdrawn",
		ReasonAACompromise:         "aACompromise",
	}

	mrSignerBlacklist = make(map[sgx.MrSigner]bool)
)

// ISVEnclaveQuoteStatus is the status of an enclave quote.
type ISVEnclaveQuoteStatus int

// Predefined ISV enclave quote status codes.
const (
	quoteFieldMissing ISVEnclaveQuoteStatus = iota
	QuoteOK
	QuoteSignatureInvalid
	QuoteGroupRevoked
	QuoteSignatureRevoked
	QuoteKeyRevoked
	QuoteSigRLVersionMismatch
	QuoteGroupOutOfDate
	QuoteConfigurationNeeded
	QuoteSwHardeningNeeded
	QuoteConfigurationAndSwHardeningNeeded
)

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (s *ISVEnclaveQuoteStatus) UnmarshalText(text []byte) error {
	var ok bool

	*s, ok = isvQuoteFwdMap[string(text)]
	if !ok {
		return fmt.Errorf("ias/avr: invalid quote status: '%v'", string(text))
	}
	return nil
}

// MarshalText implements the encoding.TextMarshaler interface.
func (s *ISVEnclaveQuoteStatus) MarshalText() ([]byte, error) {
	str, ok := isvQuoteRevMap[*s]
	if !ok {
		return nil, fmt.Errorf("ias/avr: invalid quote status: '%v'", int(*s))
	}

	return []byte(str), nil
}

func (s ISVEnclaveQuoteStatus) String() string {
	return isvQuoteRevMap[s]
}

// PSEManifestStatus is the status of a SGX Platform Service Security
// Property Descriptor.
type PSEManifestStatus int

// Predefined SGX Platform Service Security Property Descriptor status codes.
const (
	ManifestOK PSEManifestStatus = iota
	ManifestUnknown
	ManifestInvalid
	ManifestOutOfDate
	ManifestRevoked
	ManifestRLVersionMismatch
)

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (p *PSEManifestStatus) UnmarshalText(text []byte) error {
	var ok bool

	*p, ok = pseManifFwdMap[string(text)]
	if !ok {
		return fmt.Errorf("ias/avr: invalid PSE manifest status: '%v'", string(text))
	}
	return nil
}

// MarshalText implements the encoding.TextMarshaler interface.
func (p *PSEManifestStatus) MarshalText() ([]byte, error) {
	str, ok := pseManifRevMap[*p]
	if !ok {
		return nil, fmt.Errorf("ias/avr: invalid PSE manifest status: '%v'", int(*p))
	}

	return []byte(str), nil
}

func (p PSEManifestStatus) String() string {
	return pseManifRevMap[p]
}

// CRLReason is a certificate revocation reason code as specified in RFC 5280
// 5.3.1.
type CRLReason int

// Predefined CRL revocation reason codes.
const (
	ReasonUnspecified          CRLReason = 0
	ReasonKeyCompromise        CRLReason = 1
	ReasonCACompromise         CRLReason = 2
	ReasonAffiliationChanged   CRLReason = 3
	ReasonSuperseded           CRLReason = 4
	ReasonCessationOfOperation CRLReason = 5
	ReasonCertificateHold      CRLReason = 6
	ReasonRemoveFromCRL        CRLReason = 8
	ReasonPrivilegeWithdrawn   CRLReason = 9
	ReasonAACompromise         CRLReason = 10
)

func (r CRLReason) String() string {
	s, ok := crlReasonRevMap[r]
	if !ok {
		return fmt.Sprintf("[unknown reason (%d)]", int(r))
	}
	return s
}

// AVRBundle is a serialized Attestation Verification Report bundled
// with additional data required to allow offline verification.
type AVRBundle struct {
	Body             []byte `json:"body"`
	CertificateChain []byte `json:"certificate_chain"`
	Signature        []byte `json:"signature"`
}

// Open decodes and validates the AVR contained in the bundle, and returns
// the Attestation Verification Report iff it is valid
func (b *AVRBundle) Open(trustRoots *x509.CertPool, ts time.Time) (*AttestationVerificationReport, error) {
	return DecodeAVR(b.Body, b.Signature, b.CertificateChain, trustRoots, ts)
}

// AttestationVerificationReport is a deserialized Attestation Verification
// Report (AVR).
type AttestationVerificationReport struct {
	ID                    string                `json:"id"`
	Timestamp             string                `json:"timestamp"`
	Version               int                   `json:"version"`
	ISVEnclaveQuoteStatus ISVEnclaveQuoteStatus `json:"isvEnclaveQuoteStatus"`
	ISVEnclaveQuoteBody   []byte                `json:"isvEnclaveQuoteBody"`
	RevocationReason      *CRLReason            `json:"revocationReason"`
	PSEManifestStatus     *PSEManifestStatus    `json:"pseManifestStatus"`
	PSEManifestHash       string                `json:"pseManifestHash"`
	PlatformInfoBlob      string                `json:"platformInfoBlob"`
	Nonce                 string                `json:"nonce"`
	EPIDPseudonym         []byte                `json:"epidPseudonym"`
	AdvisoryURL           string                `json:"advisoryURL"`
	AdvisoryIDs           []string              `json:"advisoryIDs"`
}

// Quote decodes and returns the enclave quote component of an Attestation
// Verification Report.
func (a *AttestationVerificationReport) Quote() (*Quote, error) {
	var quote Quote
	if err := quote.UnmarshalBinary(a.ISVEnclaveQuoteBody); err != nil {
		return nil, err
	}
	return &quote, nil
}

func (a *AttestationVerificationReport) validate() error { // nolint: gocyclo
	const (
		pseManifestHashLen = 32
		epidPseudonymLen   = 64 + 64
	)

	if _, err := time.Parse(TimestampFormat, a.Timestamp); err != nil {
		return fmt.Errorf("ias/avr: invalid timestamp: %w", err)
	}

	if a.Version != requiredAVRVersion {
		return fmt.Errorf("ias/avr: invalid report version, got: %d, required: %d", a.Version, requiredAVRVersion)
	}

	if a.ISVEnclaveQuoteStatus == quoteFieldMissing {
		return fmt.Errorf("ias/avr: missing isvEnclaveQuoteStatus")
	}

	switch len(a.ISVEnclaveQuoteBody) {
	case 0:
	case quoteLen:
		untrustedQuote, err := a.Quote()
		if err != nil {
			return fmt.Errorf("ias/avr: malformed quote: %w", err)
		}
		if err = untrustedQuote.Verify(); err != nil {
			return fmt.Errorf("ias/avr: invalid quote: %w", err)
		}
	default:
		return fmt.Errorf("ias/avr: invalid isvEnclaveQuoteBody length")
	}

	if a.ISVEnclaveQuoteStatus == QuoteGroupRevoked {
		if a.RevocationReason == nil {
			return fmt.Errorf("ias/avr: missing revocationReason")
		}
	} else if a.RevocationReason != nil {
		return fmt.Errorf("ias/avr: invalid isvEnclaveStatus for revocationReason")
	}

	if a.PSEManifestStatus != nil {
		switch a.ISVEnclaveQuoteStatus {
		case QuoteOK, QuoteGroupOutOfDate, QuoteConfigurationNeeded, QuoteSwHardeningNeeded, QuoteConfigurationAndSwHardeningNeeded:
		default:
			return fmt.Errorf("ias/avr: unexpected pseManifestStatus")
		}
	}

	pseHash, err := hex.DecodeString(a.PSEManifestHash)
	if err != nil {
		return fmt.Errorf("ias/avr: failed to decode pseManifestHash: %w", err)
	}
	switch len(pseHash) {
	case 0, pseManifestHashLen:
	default:
		return fmt.Errorf("ias/avr: invalid pseManifestHash length")
	}

	piBlob, err := hex.DecodeString(a.PlatformInfoBlob)
	if err != nil {
		return fmt.Errorf("ias/avr: failed to decode platformInfoBlob: %w", err)
	}
	if len(piBlob) > 0 {
		var canHas bool

		switch a.ISVEnclaveQuoteStatus {
		case QuoteGroupRevoked, QuoteGroupOutOfDate, QuoteConfigurationNeeded, QuoteSwHardeningNeeded, QuoteConfigurationAndSwHardeningNeeded:
			canHas = true
		default:
		}

		if a.PSEManifestStatus != nil && !canHas { // "one of the following"
			switch *a.PSEManifestStatus {
			case ManifestOutOfDate, ManifestRevoked, ManifestRLVersionMismatch:
				canHas = true
			default:
			}
		}

		if !canHas {
			return fmt.Errorf("ias/avr: unexpected platformInfoBlob")
		}

		// Could validate the Platform Info Blob (4.2.4), but it's also
		// described as "opaque".
	}

	if len(a.Nonce) > NonceMaxLen {
		return fmt.Errorf("ias/avr: invalid nonce length")
	}

	switch len(a.EPIDPseudonym) {
	case 0, epidPseudonymLen:
	default:
		return fmt.Errorf("ias/avr: invalid epidPseudonym length")
	}

	return nil
}

// DecodeAVR decodes and validates an Attestation Verification Report.
func DecodeAVR(data, encodedSignature, encodedCertChain []byte, trustRoots *x509.CertPool, ts time.Time) (*AttestationVerificationReport, error) {
	if !unsafeSkipVerify {
		if err := validateAVRSignature(data, encodedSignature, encodedCertChain, trustRoots, ts); err != nil {
			return nil, err
		}
	}

	// Set the ISVEnclaveQuoteStatus to a sentinel value so that it is
	// possible to detect it being missing from the JSON.
	a := &AttestationVerificationReport{
		ISVEnclaveQuoteStatus: quoteFieldMissing,
	}

	if err := json.Unmarshal(data, a); err != nil {
		return nil, fmt.Errorf("ias/avr: failed to parse JSON: %w", err)
	}

	if err := a.validate(); err != nil {
		return nil, err
	}

	return a, nil
}

func validateAVRSignature(data, encodedSignature, encodedCertChain []byte, trustRoots *x509.CertPool, ts time.Time) error {
	decoded, err := url.QueryUnescape(string(encodedCertChain))
	if err != nil {
		return fmt.Errorf("ias/avr: failed to decode certificate chain: %w", err)
	}
	pemCerts := []byte(decoded)

	var certs []*x509.Certificate
	for {
		var cert *x509.Certificate
		cert, pemCerts, err = CertFromPEM(pemCerts)
		if err != nil {
			return err
		}
		if cert == nil {
			break
		}
		certs = append(certs, cert)
	}
	if len(certs) != 2 {
		return fmt.Errorf("ias/avr: unexpected certificate chain length: %d", len(certs))
	}

	signingCert, rootCert := certs[0], certs[1]
	certChains, err := signingCert.Verify(x509.VerifyOptions{
		Roots:       trustRoots,
		CurrentTime: ts,
	})
	if err != nil {
		return fmt.Errorf("ias/avr: failed to verify certificate chain: %w", err)
	}
	if !certRootsAChain(rootCert, certChains) {
		return fmt.Errorf("ias/avr: unexpected root in certificate chain")
	}

	signature, err := base64.StdEncoding.DecodeString(string(encodedSignature))
	if err != nil {
		return fmt.Errorf("ias/avr: failed to decode signature: %w", err)
	}

	if err = signingCert.CheckSignature(x509.SHA256WithRSA, data, signature); err != nil {
		return fmt.Errorf("ias/avr: failed to verify AVR signature: %w", err)
	}

	return nil
}

// SetSkipVerify will disable AVR signature verification for the remainder
// of the process' lifetime.
func SetSkipVerify() {
	unsafeSkipVerify = true
}

// SetAllowDebugEnclave will enable running and communicating with enclaves
// with debug flag enabled in AVR for the remainder of the process' lifetime.
func SetAllowDebugEnclaves() {
	unsafeAllowDebugEnclaves = true
}

// UnsetAllowDebugEnclave will disable running and communicating with enclaves
// with debug flag enabled in AVR for the remainder of the process' lifetime.
func UnsetAllowDebugEnclaves() {
	unsafeAllowDebugEnclaves = false
}

// BuildMrSignerBlacklist builds the MRSIGNER blacklist.
func BuildMrSignerBlacklist(allowTestKeys bool) {
	if !allowTestKeys {
		for _, v := range []string{
			sgx.FortanixDummyMrSigner.String(),
		} {
			var signer sgx.MrSigner
			if err := signer.UnmarshalHex(v); err != nil {
				panic("ias/avr: failed to decode MRSIGNER: " + v)
			}
			mrSignerBlacklist[signer] = true
		}
	}
}

func init() {
	for k, v := range isvQuoteFwdMap {
		isvQuoteRevMap[v] = k
	}
	for k, v := range pseManifFwdMap {
		pseManifRevMap[v] = k
	}
}
