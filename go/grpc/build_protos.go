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
	"strings"
)

// protoFiles is the vector of vectors containing the protobuf source file(s)
// that will be passed to each invocation of protoc, relative to the `ekiden`
// directory.
//
// It is assumed that each proto file explicitly specifies the Go package
// via the `option go_package` directive.
var protoFiles = [][]string{
	{"go/grpc/beacon/beacon.proto"},
	{"common/api/src/common.proto"},
	{"go/grpc/dummydebug/dummy_debug.proto"},
	{
		"registry/api/src/runtime.proto",
		"registry/api/src/entity.proto",
	},
	{"roothash/api/src/roothash.proto"},
	{"scheduler/api/src/scheduler.proto"},
	{"storage/api/src/storage.proto"},
}

//
// Edit below here at your peril.  It should be sufficient to merely add files
// to `protoFiles`.
//

const protocIncludePath = "../../"

func abortOnErr(err error) {
	fmt.Fprintf(os.Stderr, "FAILED: %v\n", err) //nolint:gas
	os.Exit(1)
}

func main() {
	// Figure out the logical working directory.  `os.Getwd()` isn't
	// good enough because it can return whatever it wants if there
	// are symlinks.
	//
	// This is done because the `ekiden` directory may be symlinked
	// into an existing $GOPATH.
	pwd := os.Getenv("PWD")
	if pwd == "" {
		abortOnErr(errors.New("Couldn't query logical working directory"))
	}
	fmt.Printf("PWD: %v\n", pwd)

	// Figure out the actual working $GOPATH.
	//
	// Merely querying $GOPATH is insufficient, because some people have
	// multiple directories specified in the env var, and this needs the
	// one that the current repo is living under.
	goPaths := filepath.SplitList(os.Getenv("GOPATH"))
	var goPath string
	if len(goPaths) == 1 {
		// If there is only one $GOPATH use it instead of doing resolution.
		goPath = goPaths[0]
	} else {
		for _, candidate := range goPaths {
			if strings.HasPrefix(pwd, candidate) {
				goPath = candidate
				break
			}
		}
	}
	if goPath == "" {
		abortOnErr(errors.New("Couldn't determine actual $GOPATH"))
	}
	fmt.Printf("GOPATH: %v\n", goPath)
	goPathSrc := filepath.Join(goPath, "src")

	for _, srcPath := range protoFiles {
		cmd := exec.Command("protoc", "-I", protocIncludePath, "--go_out=plugins=grpc:"+goPathSrc) //nolint:gas
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
