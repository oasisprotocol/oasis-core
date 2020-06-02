package transaction

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/quantity"
)

func TestFeeGasPrice(t *testing.T) {
	// Test large Gas field.
	var amt quantity.Quantity
	require.NoError(t, amt.FromUint64(0x9000000000000000), "import amount")
	gasPrice := Fee{
		Amount: amt,
		Gas:    0x9000000000000000,
	}.GasPrice()
	var referencePrice quantity.Quantity
	require.NoError(t, referencePrice.FromUint64(1), "import reference price")
	require.Zero(t, gasPrice.Cmp(&referencePrice), "price matches")
}
