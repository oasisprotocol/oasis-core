package stateless

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/light"
)

func TestVerification(t *testing.T) {
	clb, err := testLightBlock()
	require.NoError(t, err, "light block generation should succeed")

	clb2, err := testNextLightBlock()
	require.NoError(t, err, "next light block generation should succeed")

	lb, err := light.DecodeLightBlock(clb)
	require.NoError(t, err, "light block decoding should succeed")

	lb2, err := light.DecodeLightBlock(clb2)
	require.NoError(t, err, "next light block decoding should succeed")

	t.Run("Block verification", func(t *testing.T) {
		blk, err := testBlock()
		require.NoError(t, err, "block generation should succeed")

		t.Run("Happy path", func(t *testing.T) {
			err = verifyBlock(blk, lb)
			require.NoError(t, err, "block verification should pass")
		})

		t.Run("Mismatched light block", func(t *testing.T) {
			err = verifyBlock(blk, lb2)
			require.Error(t, err, "block verification should fail")
			require.ErrorContains(t, err, "mismatched block height")
		})

		type testCase struct {
			name   string
			err    string
			modify func(blk *consensus.Block)
		}

		testCases := []testCase{
			{
				name: "Mismatched height",
				err:  "mismatched block height",
				modify: func(blk *consensus.Block) {
					blk.Height++
				},
			},
			{
				name: "Mismatched hash",
				err:  "mismatched block hash",
				modify: func(blk *consensus.Block) {
					blk.Hash = hash.Hash{1, 2, 3}
				},
			},
			{
				name: "Mismatched time",
				err:  "mismatched block time",
				modify: func(blk *consensus.Block) {
					blk.Time = time.Now()
				},
			},
			{
				name: "Mismatched state root namespace",
				err:  "mismatched block state root namespace",
				modify: func(blk *consensus.Block) {
					blk.StateRoot.Namespace[0]++
				},
			},
			{
				name: "Mismatched state root version",
				err:  "mismatched block state root version",
				modify: func(blk *consensus.Block) {
					blk.StateRoot.Version++
				},
			},
			{
				name: "Mismatched state root type",
				err:  "mismatched block state root type",
				modify: func(blk *consensus.Block) {
					blk.StateRoot.Type++
				},
			},
			{
				name: "Mismatched state root hash",
				err:  "mismatched block state root hash",
				modify: func(blk *consensus.Block) {
					blk.StateRoot.Hash[0]++
				},
			},
			{
				name: "Malformed block meta",
				err:  "malformed block meta",
				modify: func(blk *consensus.Block) {
					blk.Meta[0]++
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				corrupted := *blk
				tc.modify(&corrupted)
				err := verifyBlock(&corrupted, lb)
				require.Error(t, err, "block verification should fail")
				require.ErrorContains(t, err, tc.err)
			})
		}
	})

	t.Run("Block results verification", func(t *testing.T) {
		results, err := testResults()
		require.NoError(t, err, "block results generation should succeed")

		t.Run("Happy path", func(t *testing.T) {
			_, err = verifyBlockResults(results, lb2.LastResultsHash, lb)
			require.NoError(t, err, "block results verification should pass")
		})

		t.Run("Mismatched light block", func(t *testing.T) {
			_, err = verifyBlockResults(results, lb2.LastResultsHash, lb2)
			require.Error(t, err, "block results verification should fail")
			require.ErrorContains(t, err, "mismatched block height")
		})

		t.Run("Mismatched results hash", func(t *testing.T) {
			_, err = verifyBlockResults(results, lb.LastResultsHash, lb)
			require.Error(t, err, "block results verification should fail")
			require.ErrorContains(t, err, "mismatched last results hash")
		})
	})

	t.Run("Transaction verification", func(t *testing.T) {
		txs, err := testTransactions()
		require.NoError(t, err, "transaction generation should succeed")

		t.Run("Happy path", func(t *testing.T) {
			err = verifyTransactions(txs, lb)
			require.NoError(t, err, "transaction verification should pass")
		})

		t.Run("Mismatched light block", func(t *testing.T) {
			err = verifyTransactions(txs, lb2)
			require.Error(t, err, "transaction verification should fail")
		})

		t.Run("Corrupted transactions", func(t *testing.T) {
			txs[0][0]++
			err = verifyTransactions(txs, lb)
			require.Error(t, err, "transaction verification should fail")
		})
	})
}

func testLightBlock() (*consensus.LightBlock, error) {
	data, err := os.ReadFile("testdata/light_block_25300000.json")
	if err != nil {
		return nil, err
	}

	var lb consensus.LightBlock
	if err := json.Unmarshal(data, &lb); err != nil {
		return nil, err
	}

	return &lb, nil
}

func testNextLightBlock() (*consensus.LightBlock, error) {
	data, err := os.ReadFile("testdata/light_block_25300001.json")
	if err != nil {
		return nil, err
	}

	var lb consensus.LightBlock
	if err := json.Unmarshal(data, &lb); err != nil {
		return nil, err
	}

	return &lb, nil
}

func testBlock() (*consensus.Block, error) {
	data, err := os.ReadFile("testdata/block_25300000.json")
	if err != nil {
		return nil, err
	}

	var blk consensus.Block
	if err := json.Unmarshal(data, &blk); err != nil {
		return nil, err
	}

	return &blk, nil
}

func testResults() (*consensus.BlockResults, error) {
	data, err := os.ReadFile("testdata/results_25300000.json")
	if err != nil {
		return nil, err
	}

	var results consensus.BlockResults
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, err
	}

	return &results, nil
}

func testTransactions() ([][]byte, error) {
	data, err := os.ReadFile("testdata/txs_25300000.json")
	if err != nil {
		return nil, err
	}

	var txs [][]byte
	if err := json.Unmarshal(data, &txs); err != nil {
		return nil, err
	}

	return txs, nil
}
