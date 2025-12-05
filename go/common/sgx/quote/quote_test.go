package quote

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestSerializationYAML(t *testing.T) {
	require := require.New(t)

	const testCase1 = `
pcs:
    disabled: false
    tcb_validity_period: 30
    min_tcb_evaluation_data_number: 17
    fmspc_whitelist:
        - "000000000000"
        - "00606A000000"
    fmspc_blacklist:
        - "000000000001"
        - "00606A000001"
`
	var dec Policy
	err := yaml.Unmarshal([]byte(testCase1), &dec)
	require.NoError(err, "yaml.Unmarshal")
	require.NotNil(dec.PCS)
	require.Nil(dec.IAS)
	require.EqualValues(false, dec.PCS.Disabled)
	require.EqualValues(30, dec.PCS.TCBValidityPeriod)
	require.EqualValues(17, dec.PCS.MinTCBEvaluationDataNumber)
	require.Len(dec.PCS.FMSPCWhitelist, 2)
	require.EqualValues("000000000000", dec.PCS.FMSPCWhitelist[0])
	require.EqualValues("00606A000000", dec.PCS.FMSPCWhitelist[1])
	require.Len(dec.PCS.FMSPCBlacklist, 2)
	require.EqualValues("000000000001", dec.PCS.FMSPCBlacklist[0])
	require.EqualValues("00606A000001", dec.PCS.FMSPCBlacklist[1])
}
