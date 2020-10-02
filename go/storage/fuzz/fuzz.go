// +build gofuzz

package fuzz

import (
	"io/ioutil"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	commonFuzz "github.com/oasisprotocol/oasis-core/go/common/fuzz"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/worker/storage"
)

const (
	dataDir     string = "/tmp/oasis-node-fuzz-storage"
	identityDir string = dataDir + "/identity"
)

var (
	storageBackend api.Backend

	fuzzer *commonFuzz.InterfaceFuzzer
)

func init() {
	signerFactory := file.NewFactory(identityDir, signature.SignerNode, signature.SignerP2P, signature.SignerConsensus)
	identity, err := identity.Load(identityDir, signerFactory)
	if err != nil {
		panic(err)
	}

	// Every Fuzz invocation should get its own database,
	// otherwise the database handles would clash.
	localDB, err := ioutil.TempDir(dataDir, "worker")
	if err != nil {
		panic(err)
	}

	// Create the storage backend service.
	storageBackend, err = storage.NewLocalBackend(localDB, common.Namespace{}, identity)
	if err != nil {
		panic(err)
	}

	// Create and prepare the fuzzer.
	fuzzer = commonFuzz.NewInterfaceFuzzer(storageBackend)
	fuzzer.IgnoreMethodNames([]string{
		"Cleanup",
		"Initialized",
	})
}

func Fuzz(data []byte) int {
	<-storageBackend.Initialized()

	fuzzer.DispatchBlob(data)

	return 0
}
