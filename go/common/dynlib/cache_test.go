// cache_test.go - Dynamic linker cache tests.
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
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

type ctorFn func() (*Cache, error)

func TestCache(t *testing.T) {
	// Obtain the path to the test executable.
	require := require.New(t)
	require.Equal("linux", runtime.GOOS, "os is linux")
	fn, err := os.Readlink("/proc/self/exe")
	require.NoError(err, "readlink(\"/proc/self/exe\")")

	t.Logf("Test binary: %+v", fn)

	v, err := GetOsVersion()
	if err == nil {
		t.Logf("OS version: %02x", v)
	}

	impls := []struct {
		name string
		ctor ctorFn
	}{
		{"glibc", loadCacheGlibc},
		{"fallback", loadCacheFallback},
	}

	for _, impl := range impls {
		t.Run(impl.name, func(t *testing.T) {
			testCacheImpl(t, impl.ctor, fn)
		})
	}
}

func testCacheImpl(t *testing.T, ctor ctorFn, fn string) {
	require := require.New(t)

	c, err := ctor()
	require.NoError(err, "Failed to enumerate system libraries")

	libs, err := c.ResolveLibraries([]string{fn}, nil, "", "", nil)
	require.NoError(err, "Failed to resolve libraries")

	t.Logf("Libraries: %+v", libs)
}
