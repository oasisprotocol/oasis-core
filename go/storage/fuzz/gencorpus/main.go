// +build gofuzz

// Gencorpus implements a simple utility to generate corpus files for the fuzzer.
// It has no command-line options and creates the files in the current working directory.
package main

import (
	"context"
	"fmt"
	"io/ioutil"

	"github.com/oasislabs/oasis-core/go/common"
	commonFuzz "github.com/oasislabs/oasis-core/go/common/fuzz"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/storage"
)

const (
	samplesPerMethod int = 20
)

func main() {
	storage, err := storage.New(context.Background(), "/tmp/oasis-node-fuzz-storage", common.Namespace{}, &identity.Identity{}, nil, nil)
	if err != nil {
		panic(err)
	}
	fuzzer := commonFuzz.NewInterfaceFuzzer(storage)
	fuzzer.IgnoreMethodNames([]string{
		"Cleanup",
		"Initialized",
	})

	for i := 0; i < samplesPerMethod; i++ {
		blobs := fuzzer.MakeSampleBlobs()
		for meth := 0; meth < len(blobs); meth++ {
			fileName := fmt.Sprintf("%s_%02d.bin", fuzzer.Method(meth).Name, i)
			_ = ioutil.WriteFile(fileName, blobs[meth], 0644)
		}
	}
}
