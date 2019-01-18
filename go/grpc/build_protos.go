// Build time "script" invoked by `go generate` to handle the fact that
// the go protoc plugin hates the fact that the `.proto` files are splattered
// throughout the Rust code, in a layout that makes sense for Rust.

// +build ignore

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	_ "strings"
)

// protoFiles is the vector of vectors containing the protobuf source file(s)
// that will be passed to each invocation of protoc, relative to the
// `ekiden/go/grpc` directory.
//
// It is assumed that each proto file explicitly specifies the Go package
// via the `option go_package` directive.
var protoFiles = [][]string{
	{"common/common.proto"},
	{"dummydebug/dummy_debug.proto"},
	{"ias/ias.proto"},
	{
		"registry/runtime.proto",
		"registry/entity.proto",
	},
	{"roothash/roothash.proto"},
	{"scheduler/scheduler.proto"},
	{"storage/storage.proto"},
	{"committee/runtime.proto"},
	{"enclaverpc/enclaverpc.proto"},
}

//
// Edit below here at your peril.  It should be sufficient to merely add files
// to `protoFiles`.
//

const protocIncludePath = "./"

func abortOnErr(err error) {
	fmt.Fprintf(os.Stderr, "FAILED: %v\n", err) //nolint:gas
	os.Exit(1)
}

func main() {
	pwd, err := os.Getwd()
	if err != nil {
		abortOnErr(errors.New("Couldn't query working directory: " + err.Error()))
	}
	fmt.Printf("PWD: %v\n", pwd)

	for _, srcPath := range protoFiles {
		cmd := exec.Command("protoc", "-I", protocIncludePath, "--go_out=plugins=grpc,paths=source_relative:.") //nolint:gas
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr

		// Fixup and append the source file paths to the arguments.
		for _, f := range srcPath {
			f = filepath.Join(protocIncludePath, f)
			cmd.Args = append(cmd.Args, f)
		}

		fmt.Printf("CMD: %+v\n", cmd.Args)
		if err := cmd.Run(); err != nil {
			abortOnErr(err)
		}
	}
}
