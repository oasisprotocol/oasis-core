package bolt

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/consensus/tendermint/db/tests"
)

func TestBoltTendermintDB(t *testing.T) {
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
