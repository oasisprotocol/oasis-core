package badger

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/db/tests"
)

func TestBadgerCometBFTDB(t *testing.T) {
	// Create a temporary directory to store the test database.
	tmpDir, err := os.MkdirTemp("", "oasis-go-cometbft-db-test")
	require.NoError(t, err, "Failed to create temporary directory.")
	defer os.RemoveAll(tmpDir)

	// Create the database.
	db, err := New(filepath.Join(tmpDir, "test"), false)
	require.NoError(t, err, "New")
	defer db.Close()

	tests.TestCometBFTDB(t, db)
}
