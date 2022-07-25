// hwcap.go - ld.so.conf hwcap routines.
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

//go:build linux
// +build linux

package dynlib

// #include <sys/auxv.h>
//
// static char * getPlatform() {
//   return (char *)getauxval(AT_PLATFORM);
// }
//
import "C"

import (
	"bytes"
	"syscall"
)

// GetOsVersion returns the operating system version (major, minor, pl).
func GetOsVersion() (uint32, error) {
	var buf syscall.Utsname
	err := syscall.Uname(&buf)
	if err != nil {
		return 0, err
	}

	// Split into a slice of digits, stopping when the first non-digit is
	// encountered.
	var relBuf []byte
	for _, v := range buf.Release {
		if (v < '0' || v > '9') && v != '.' {
			break
		}
		relBuf = append(relBuf, byte(v))
	}

	// Parse major, minor, pl into bytes, and jam them together.
	//
	// glibc as far as I can tell doesn't handle any of versions being larger
	// than 256 at all.
	var ret uint32
	appended := uint(0)
	for i, v := range bytes.Split(relBuf, []byte{'.'}) {
		if i > 2 {
			break
		}
		var subVer uint8
		for _, b := range v {
			subVer = subVer * 10
			subVer = subVer + (b - '0')
		}
		ret = ret << 8
		ret = ret | uint32(subVer)
		appended++
	}
	return ret << (8 * (3 - appended)), nil
}
