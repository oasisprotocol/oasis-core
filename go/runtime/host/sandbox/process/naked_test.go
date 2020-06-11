package process

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNakedSandbox(t *testing.T) {
	t.Run("BindData", func(t *testing.T) {
		testBindData(t, NewNaked, "")
	})
}

func testBindData(t *testing.T, factory func(Config) (Process, error), sandboxBinary string) {
	require := require.New(t)

	dir, err := ioutil.TempDir("", "oasis-runtime-host-sandbox-test_")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dir)

	boundPath := filepath.Join(dir, "does", "not", "yet", "exist", "bound.data")

	// Bind some data from a buffer and run /bin/cat inside the sandbox to make sure it's there.
	var stdout bytes.Buffer
	p, err := factory(Config{
		Path: "/bin/cat",
		Args: []string{boundPath},
		BindData: map[string]io.Reader{
			boundPath: bytes.NewBufferString("hello world"),
		},
		Stdout:            &stdout,
		SandboxBinaryPath: sandboxBinary,
	})
	require.NoError(err, "NewNaked")

	// Wait for the process to exit and make sure it succeeded.
	<-p.Wait()
	err = p.Error()
	require.NoError(err, "process should execute successfully")

	// Make sure output was correct.
	require.EqualValues("hello world", stdout.Bytes())
}
