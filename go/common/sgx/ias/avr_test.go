package ias

import (
	"encoding/base64"
	"io/ioutil"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAVR(t *testing.T) {
	t.Run("Version_4", testAVRv4)
}

func testAVRv4(t *testing.T) {
	// TODO: Generate and test production AVR without debug bit.
	SetAllowDebugEnclaves()
	defer UnsetAllowDebugEnclaves()

	raw, sig, certs := loadAVRv4(t)

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

func loadAVRv4(t *testing.T) (raw, sig, certs []byte) {
	var err error
	raw, err = ioutil.ReadFile("testdata/avr_v4_body_sw_hardening_needed.json")
	require.NoError(t, err, "Read test vector")

	sig, err = ioutil.ReadFile("testdata/avr_v4_body_sw_hardening_needed.sig")
	require.NoError(t, err, "Read signature")

	certs, err = ioutil.ReadFile("testdata/avr_certificates_urlencoded.pem")
	require.NoError(t, err, "Read certificate chain")

	return
}
