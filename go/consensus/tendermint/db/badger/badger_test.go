package badger

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/iavl"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/db/tests"
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

func TestBadgerPrune(t *testing.T) {
	require.NoError(t, logging.Initialize(os.Stdout, logging.FmtJSON, logging.LevelDebug, nil), "logging.Initialize")
	db, err := New("../../../../../../iavl/untracked/active/abci-mux-state", false)
	require.NoError(t, err, "New")
	defer db.Close()

	tree := iavl.NewMutableTree(db, 128)
	eldestVersion := tree.EldestVersion()
	fmt.Printf("eldest version %v\n", eldestVersion)

	fmt.Println("pruning")
	require.NoError(t, tree.DeleteVersion(eldestVersion), "tree.DeleteVersion")
	fmt.Println("done")
}
