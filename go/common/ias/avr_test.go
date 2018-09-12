package ias

import (
	"encoding/base64"
	"io/ioutil"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAVR(t *testing.T) {
	t.Run("Version_2", testAVRv2)
}

func testAVRv2(t *testing.T) {
	raw, err := ioutil.ReadFile("testdata/avr_v2_body_group_out_of_date.json")
	require.NoError(t, err, "Read test vector")

	sig, err := ioutil.ReadFile("testdata/avr_v2_body_group_out_of_date.sig")
	require.NoError(t, err, "Read signature")

	certs, err := ioutil.ReadFile("testdata/avr_certificates_urlencoded.pem")
	require.NoError(t, err, "Read certificate chain")

	avr, err := DecodeAVR(raw, sig, certs, time.Now())
	require.NoError(t, err, "DecodeAVR")

	require.Equal(t, "297344624956134022721154881818462408967", avr.ID, "id")
	require.Equal(t, "2018-03-30T22:02:25.579777", avr.Timestamp, "timestamp")
	require.Equal(t, 0, avr.Version, "version")
	require.Equal(t, QuoteGroupOutOfDate, avr.ISVEnclaveQuoteStatus, "isvEnclaveQuoteStatus")
	require.Len(t, avr.ISVEnclaveQuoteBody, 432, "isvEnclaveQuoteBody")
	require.Nil(t, avr.RevocationReason, "revocationReason")
	require.Nil(t, avr.PSEManifestStatus, "pseManifestStatus")
	require.Equal(t, "", avr.PSEManifestHash, "pseManifestHash")
	require.Equal(
		t,
		"1502006504000500000707010101010000000000000000000005000006000000020000000000000AE320D6C7982E25472A523A7B1195454A7D06FA9C533A68115EF1F5AB9F47E31A94BFF62CD4D4109751413211E4AB12822173BCA5F73006FC64A02BFBA6501E300F",
		avr.PlatformInfoBlob,
		"platformInfoBlob",
	)
	require.Equal(t, "", avr.Nonce, "nonce")

	epidPseudonym, _ := base64.StdEncoding.DecodeString("auQFGj3IeH7TlfmxhO0QLcXzGppYufXjzWKyNXHnoXp5+jGvusQJV+4PjbNYxb8HJm3LLKu3iu/4nvcMLkVXsPVM96Faafv7cSmwkNla1X9v2ei7C+5LN+EXgAJXpZVjTkCvD0WyPo+NmDRWVJeu83aDb+ktEiafMGo34Zk4m4Q=")
	require.Equal(t, epidPseudonym, avr.EPIDPseudonym, "epidPseudonym")
}
