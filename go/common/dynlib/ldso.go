// ldso.go - Dynamic linker routines.
// Copyright 2016 Yawning Angel
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

package dynlib

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

var errUnsupported = errors.New("dynlib: unsupported os/architecture")

func getLibraries(fn string) ([]string, error) {
	f, err := elf.Open(fn)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return f.ImportedLibraries()
}

// ValidateLibraryClass ensures that the library matches the current
// architecture.
func ValidateLibraryClass(fn string) error {
	f, err := elf.Open(fn)
	if err != nil {
		return err
	}
	defer f.Close()

	var expectedClass elf.Class
	switch runtime.GOARCH {
	case archAmd64:
		expectedClass = elf.ELFCLASS64
	default:
		return errUnsupported
	}

	if f.Class != expectedClass {
		return fmt.Errorf("unsupported class: %v: %v", fn, f.Class)
	}
	return nil
}

// FindLdSo returns the path to the `ld.so` dynamic linker for the current
// architecture, which is usually a symlink
func FindLdSo(cache *Cache) (string, string, error) {
	if !IsSupported() {
		return "", "", errUnsupported
	}

	name := ""
	searchPaths := []string{}
	switch runtime.GOARCH {
	case archAmd64:
		searchPaths = append(searchPaths, "/lib64")
		name = "ld-linux-x86-64.so.2"
	default:
		panic("dynlib: unsupported architecture: " + runtime.GOARCH)
	}
	searchPaths = append(searchPaths, "/lib")

	for _, d := range searchPaths {
		candidate := filepath.Join(d, name)
		_, err := os.Stat(candidate)
		if err != nil {
			continue
		}

		actual := cache.GetLibraryPath(name)
		if actual == "" {
			continue
		}
		actual, err = filepath.EvalSymlinks(actual)

		return actual, candidate, err
	}

	return "", "", os.ErrNotExist
}

// IsSupported returns true if the architecture/os combination has dynlib
// support.
func IsSupported() bool {
	return runtime.GOOS == "linux" && runtime.GOARCH == archAmd64
}
