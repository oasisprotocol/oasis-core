package pcs

import (
	"encoding/binary"
	"fmt"
)

// mockCertificationDataChain is the certificate chain that is used when generating mock quotes. The
// chain is valid and rooted in an Intel root CA, but the mock quote is not actually signed by the
// leaf PCK certificate key (that would require breaking SGX).
const mockCertificationDataChain = `-----BEGIN CERTIFICATE-----
MIIE8TCCBJigAwIBAgIUCwzf8Y277g/WBsYNs2mJm+5A08cwCgYIKoZIzj0EAwIw
cDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBQbGF0Zm9ybSBDQTEaMBgGA1UECgwR
SW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQI
DAJDQTELMAkGA1UEBhMCVVMwHhcNMjIxMjA1MTExMjAxWhcNMjkxMjA1MTExMjAx
WjBwMSIwIAYDVQQDDBlJbnRlbCBTR1ggUENLIENlcnRpZmljYXRlMRowGAYDVQQK
DBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV
BAgMAkNBMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOvx
26Sde13RLMxQyLy4j0T0UBLiAdOyZlVUIr8mwyHfLB6rH9GttxGmFW+wcQihRx0M
fRaDYnX0neNnqIKC2xajggMOMIIDCjAfBgNVHSMEGDAWgBSVb13NvRvh6UBJydT0
M84BVwveVDBrBgNVHR8EZDBiMGCgXqBchlpodHRwczovL2FwaS50cnVzdGVkc2Vy
dmljZXMuaW50ZWwuY29tL3NneC9jZXJ0aWZpY2F0aW9uL3YzL3Bja2NybD9jYT1w
bGF0Zm9ybSZlbmNvZGluZz1kZXIwHQYDVR0OBBYEFBeR46rJwx3KTy/81Y86HpH0
U1UTMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMIICOwYJKoZIhvhNAQ0B
BIICLDCCAigwHgYKKoZIhvhNAQ0BAQQQ87e/hHImL0xsfPTInwoqnDCCAWUGCiqG
SIb4TQENAQIwggFVMBAGCyqGSIb4TQENAQIBAgEHMBAGCyqGSIb4TQENAQICAgEJ
MBAGCyqGSIb4TQENAQIDAgEDMBAGCyqGSIb4TQENAQIEAgEDMBEGCyqGSIb4TQEN
AQIFAgIA/zARBgsqhkiG+E0BDQECBgICAP8wEAYLKoZIhvhNAQ0BAgcCAQEwEAYL
KoZIhvhNAQ0BAggCAQAwEAYLKoZIhvhNAQ0BAgkCAQAwEAYLKoZIhvhNAQ0BAgoC
AQAwEAYLKoZIhvhNAQ0BAgsCAQAwEAYLKoZIhvhNAQ0BAgwCAQAwEAYLKoZIhvhN
AQ0BAg0CAQAwEAYLKoZIhvhNAQ0BAg4CAQAwEAYLKoZIhvhNAQ0BAg8CAQAwEAYL
KoZIhvhNAQ0BAhACAQAwEAYLKoZIhvhNAQ0BAhECAQ0wHwYLKoZIhvhNAQ0BAhIE
EAcJAwP//wEAAAAAAAAAAAAwEAYKKoZIhvhNAQ0BAwQCAAAwFAYKKoZIhvhNAQ0B
BAQGAGBqAAAAMA8GCiqGSIb4TQENAQUKAQEwHgYKKoZIhvhNAQ0BBgQQ8wa5BmQs
MNTTXpvW7RMftjBEBgoqhkiG+E0BDQEHMDYwEAYLKoZIhvhNAQ0BBwEBAf8wEAYL
KoZIhvhNAQ0BBwIBAQAwEAYLKoZIhvhNAQ0BBwMBAQAwCgYIKoZIzj0EAwIDRwAw
RAIgTSN7Vw8hhZTzRTELlTvii/ZmRWjDuCZmnfZb8SwxxRsCICwXybdLaxF3BHSl
KZIwLTCGounNHXDkSJfxM/lKnsnY
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICljCCAj2gAwIBAgIVAJVvXc29G+HpQEnJ1PQzzgFXC95UMAoGCCqGSM49BAMC
MGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBD
b3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQsw
CQYDVQQGEwJVUzAeFw0xODA1MjExMDUwMTBaFw0zMzA1MjExMDUwMTBaMHAxIjAg
BgNVBAMMGUludGVsIFNHWCBQQ0sgUGxhdGZvcm0gQ0ExGjAYBgNVBAoMEUludGVs
IENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0Ex
CzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENSB/7t21lXSO
2Cuzpxw74eJB72EyDGgW5rXCtx2tVTLq6hKk6z+UiRZCnqR7psOvgqFeSxlmTlJl
eTmi2WYz3qOBuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBS
BgNVHR8ESzBJMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2Vy
dmljZXMuaW50ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUlW9d
zb0b4elAScnU9DPOAVcL3lQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYB
Af8CAQAwCgYIKoZIzj0EAwIDRwAwRAIgXsVki0w+i6VYGW3UF/22uaXe0YJDj1Ue
nA+TjD1ai5cCICYb1SAmD5xkfTVpvo4UoyiSYxrDWLmUR4CI9NKyfPN+
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----`

// reportBodyWithMacLen is the length of the report together with keyid and MAC.
const reportBodyWithMacLen = 432

// NewMockQuote generates a mock quote from the given report, after doing some light sanity checking
// on the report.
//
// This is only useful for runtimes with quote verification disabled at compile time (ie: built with
// `OASIS_UNSAFE_SKIP_AVR_VERIFY=1`).
func NewMockQuote(rawReport []byte) ([]byte, error) {
	// Sanity check report size.
	switch len(rawReport) {
	case reportBodyWithMacLen:
		// If the raw report contains a MAC, truncate it as the MAC is meant for QE authentication
		// which we don't need to verify.
		rawReport = rawReport[:reportBodySgxLen]
	case reportBodySgxLen:
	default:
		return nil, fmt.Errorf("invalid report size: %d", len(rawReport))
	}

	// Sanity check report.
	var report SgxReport
	if err := report.UnmarshalBinary(rawReport); err != nil {
		return nil, err
	}

	// Quote header.
	var header [quoteHeaderLen]byte
	binary.LittleEndian.PutUint16(header[0:], 3)                                // Version.
	binary.LittleEndian.PutUint16(header[2:], uint16(AttestationKeyECDSA_P256)) // Attestation key type.
	binary.LittleEndian.PutUint32(header[4:], 0)                                // Reserved.
	binary.LittleEndian.PutUint16(header[8:], 9)                                // QESVN.
	binary.LittleEndian.PutUint16(header[10:], 13)                              // PCESVN.
	copy(header[12:], QEVendorID_Intel)                                         // QE vendor ID.
	// User data (leave as null).

	// Mock signature (we cannot generate valid ones).
	var signature [quoteSigEcdsaP256MinLen + len(mockCertificationDataChain)]byte
	binary.LittleEndian.PutUint16(signature[576:], 0)                                       // Authentication data size.
	binary.LittleEndian.PutUint16(signature[578:], CertificationDataPCKCertificateChain)    // Certification data type.
	binary.LittleEndian.PutUint32(signature[580:], uint32(len(mockCertificationDataChain))) // Certification data size.
	copy(signature[584:], []byte(mockCertificationDataChain))

	// Put together a quote.
	quote := append(header[:], rawReport...)

	var sigLen [4]byte
	binary.LittleEndian.PutUint32(sigLen[:], uint32(len(signature)))
	quote = append(quote, sigLen[:]...)
	quote = append(quote, signature[:]...)

	return quote, nil
}
