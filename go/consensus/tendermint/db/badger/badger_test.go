package badger

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/db/tests"
)

func TestBadgerTendermintDB(t *testing.T) {
	// Create a temporary directory to store the test database.
	tmpDir, err := ioutil.TempDir("", "oasis-go-tendermint-db-test")
	require.NoError(t, err, "Failed to create temporary directory.")
	defer os.RemoveAll(tmpDir)

	// Create the database.
	db, err := New(filepath.Join(tmpDir, "test"), false)
	require.NoError(t, err, "New")
	defer db.Close()

	tests.TestTendermintDB(t, db)
}
