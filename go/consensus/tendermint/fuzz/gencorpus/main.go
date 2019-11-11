// +build gofuzz

// Gencorpus implements a simple utility to generate corpus files for the fuzzer.
// It has no command-line options and creates the files in the current working directory.
package main

import (
	"fmt"
	"io/ioutil"

	commonFuzz "github.com/oasislabs/oasis-core/go/common/fuzz"
	appFuzz "github.com/oasislabs/oasis-core/go/consensus/tendermint/fuzz"
)

const (
	samplesPerMethod int = 20
)

func main() {
	for meth := 0; meth < len(appFuzz.FuzzableMethods); meth++ {
		for i := 0; i < samplesPerMethod; i++ {
			methodName := appFuzz.FuzzableMethods[meth]

			fmt.Println("generating sample", i, "for method", methodName)

			actualSample := []byte{byte(meth)}
			actualSample = append(actualSample, commonFuzz.MakeSampleBlob(methodName.BodyType())...)
			fileName := fmt.Sprintf("%02d_%s_%02d.bin", meth, string(methodName), i)
			_ = ioutil.WriteFile(fileName, actualSample, 0644)
		}
	}
}
