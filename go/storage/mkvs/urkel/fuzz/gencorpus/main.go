// +build gofuzz

// Gencorpus implements a simple utility to generate corpus files for the fuzzer.
// It has no command-line options and creates the files in the current working directory.
package main

import (
	"fmt"
	"io/ioutil"

	commonFuzz "github.com/oasislabs/oasis-core/go/common/fuzz"
	mkvsFuzz "github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/fuzz"
)

const (
	samplesPerMethod int = 20
)

func main() {
	tree := mkvsFuzz.NewTreeFuzz()
	fuzzer := commonFuzz.NewInterfaceFuzzer(tree)

	for i := 0; i < samplesPerMethod; i++ {
		blobs := fuzzer.MakeSampleBlobs()
		for meth := 0; meth < len(blobs); meth++ {
			fileName := fmt.Sprintf("%s_%02d.bin", fuzzer.Method(meth).Name, i)
			_ = ioutil.WriteFile(fileName, blobs[meth], 0644)
		}
	}
}
