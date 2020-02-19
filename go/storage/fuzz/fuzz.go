// +build gofuzz

package fuzz

import (
	"context"
	"io/ioutil"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/file"
	commonFuzz "github.com/oasislabs/oasis-core/go/common/fuzz"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/storage"
	"github.com/oasislabs/oasis-core/go/storage/api"
)

const (
	dataDir string = "/tmp/oasis-node-fuzz-storage"
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
	storageBackend, err = storage.New(context.Background(), localDB, common.Namespace{}, identity, nil, nil)
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
