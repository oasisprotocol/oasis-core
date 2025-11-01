package ias

import (
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAVR(t *testing.T) {
	t.Run("Version_4", testAVRv4)
	t.Run("Version_5", testAVRv5)
}

func testAVRv4(t *testing.T) {
	// TODO: Generate and test production AVR without debug bit.
	SetAllowDebugEnclaves()
	defer UnsetAllowDebugEnclaves()

	raw, sig, certs := loadAVR(t, 4)

	avr, err := DecodeAVR(raw, sig, certs, IntelTrustRoots, time.Now())
	require.NoError(t, err, "DecodeAVR")

	require.Equal(t, "323119119247496566074708526703373820736", avr.ID, "id")
	require.Equal(t, "2020-05-11T09:21:15.454051", avr.Timestamp, "timestamp")
	require.Equal(t, 4, avr.Version, "version")
	require.Equal(t, QuoteSwHardeningNeeded, avr.ISVEnclaveQuoteStatus, "isvEnclaveQuoteStatus")
	require.Len(t, avr.ISVEnclaveQuoteBody, 432, "isvEnclaveQuoteBody")
	require.Nil(t, avr.RevocationReason, "revocationReason")
	require.Nil(t, avr.PSEManifestStatus, "pseManifestStatus")
	require.Equal(t, "", avr.PSEManifestHash, "pseManifestHash")
	require.Equal(t, "", avr.PlatformInfoBlob, "platformInfoBlob")
	require.Equal(t, "biNMqBAuTPF2hp/0fXa4P3splRkLHJf0", avr.Nonce, "nonce")

	epidPseudonym, _ := base64.StdEncoding.DecodeString("uAFRLXADu90LsPq9Btgx8MWUPOzmDHE51pwLlUlU3hzFUk2EmvWpF6fZsyokOVkQUJ0UwZk0nCF8XPaCcSmLwqXAzLa+n/K7TdwlxKofEyTgG8da8mmrShNoFw3BSD74wSA4aAc753IfrbnnmuYk00lkmSUOTzqsqHlAORcweqg=")
	require.Equal(t, epidPseudonym, avr.EPIDPseudonym, "epidPseudonym")

	require.Equal(t, avr.AdvisoryURL, "https://security-center.intel.com", "advisoryURL")
	require.EqualValues(t, avr.AdvisoryIDs, []string{"INTEL-SA-00334"}, "advisoryIDs")
}

func testAVRv5(t *testing.T) {
	// TODO: Generate and test production AVR without debug bit.
	SetAllowDebugEnclaves()
	defer UnsetAllowDebugEnclaves()

	raw, sig, certs := loadAVR(t, 5)

	avr, err := DecodeAVR(raw, sig, certs, IntelTrustRoots, time.Now())
	require.NoError(t, err, "DecodeAVR")

	require.Equal(t, "325753020347524304899139732345489823748", avr.ID, "id")
	require.Equal(t, "2023-09-27T15:51:58.044803", avr.Timestamp, "timestamp")
	require.Equal(t, 5, avr.Version, "version")
	require.Equal(t, QuoteSwHardeningNeeded, avr.ISVEnclaveQuoteStatus, "isvEnclaveQuoteStatus")
	require.Len(t, avr.ISVEnclaveQuoteBody, 432, "isvEnclaveQuoteBody")
	require.Nil(t, avr.RevocationReason, "revocationReason")
	require.Nil(t, avr.PSEManifestStatus, "pseManifestStatus")
	require.Equal(t, "", avr.PSEManifestHash, "pseManifestHash")
	require.Equal(t, "", avr.PlatformInfoBlob, "platformInfoBlob")
	require.Equal(t, "", avr.Nonce, "nonce")

	epidPseudonym, _ := base64.StdEncoding.DecodeString("twLvZuBD1sOHsNPsHGbZOVlGh9rXw9XzVQTVKUuvsqypw0iWcFKwR7aNoHmDSoeFc/+pH6LLCI2bQBKx/ygwXphePD4GTTRwBi9EIBFRlURTk4p4NosbA7xcCG4hRuCDaEKPtAX6XHjNKEvWA+4f1aAfD7jwOtGAzHeaqBldaD8=")
	require.Equal(t, epidPseudonym, avr.EPIDPseudonym, "epidPseudonym")

	require.Equal(t, avr.AdvisoryURL, "https://security-center.intel.com", "advisoryURL")
	require.EqualValues(t, avr.AdvisoryIDs, []string{"INTEL-SA-00334", "INTEL-SA-00615"}, "advisoryIDs")
}

func loadAVR(t *testing.T, version int) (raw, sig, certs []byte) {
	var err error
	raw, err = os.ReadFile(fmt.Sprintf("testdata/avr_v%v_body_sw_hardening_needed.json", version))
	require.NoError(t, err, "Read test vector")

	sig, err = os.ReadFile(fmt.Sprintf("testdata/avr_v%v_body_sw_hardening_needed.sig", version))
	require.NoError(t, err, "Read signature")

	certs, err = os.ReadFile("testdata/avr_certificates_urlencoded.pem")
	require.NoError(t, err, "Read certificate chain")

	return raw, sig, certs
}
