// cache.go - Dynamic linker cache routines.
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

// Package dynlib provides routines for interacting with the glibc ld.so dynamic
// linker/loader.
package dynlib

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const (
	ldSoCache = "/etc/ld.so.cache"

	flagX8664Lib64 = 0x0300
	// flagElf      = 1
	flagElfLibc6 = 3

	archAmd64 = "amd64"
)

var (
	// Debugf is a hook used for redirecting debug output.
	Debugf func(string, ...interface{})

	cacheMagic = []byte{
		'l', 'd', '.', 's', 'o', '-', '1', '.', '7', '.', '0', 0,
	}

	cacheMagicNew = []byte{
		'g', 'l', 'i', 'b', 'c', '-', 'l', 'd', '.', 's', 'o', '.', 'c', 'a', 'c',
		'h', 'e', '1', '.', '1',
	}
)

// FilterFunc is a function that implements a filter to allow rejecting
// dependencies when resolving libraries.
type FilterFunc func(string) error

// Quoting from sysdeps/generic/dl-cache.h:
//
// libc5 and glibc 2.0/2.1 use the same format.  For glibc 2.2 another
// format has been added in a compatible way:
// The beginning of the string table is used for the new table:
//   old_magic
//   nlibs
//   libs[0]
//   ...
//   libs[nlibs-1]
//   pad, new magic needs to be aligned
//	     - this is string[0] for the old format
//   new magic - this is string[0] for the new format
//   newnlibs    (uint32_t)
//   newnstrings (uint32_t)
//   unused      (20 bytes)
//   newlibs[0]
//   ...
//   newlibs[newnlibs-1]
//   string 1
//   string 2
//   ...
//
// From glibc 2.32 the default behavior is to omit support for backward
// compatibility, by just starting at `new magic`, without the old header.

// Cache is a representation of the `ld.so.cache` file.
type Cache struct {
	store map[string]cacheEntries
}

// GetLibraryPath returns the path to the given library, if any.  This routine
// makes no attempt to disambiguate multiple libraries (eg: via hwcap/search
// path).
func (c *Cache) GetLibraryPath(name string) string {
	ents, ok := c.store[name]
	if !ok {
		return ""
	}

	return ents[0].value
}

// ResolveLibraries returns a map of library paths and their aliases for a
// given set of binaries, based off the ld.so.cache, libraries known to be
// internal, and a search path.
func (c *Cache) ResolveLibraries(binaries []string, extraLibs []string, ldLibraryPath, fallbackSearchPath string, filterFn FilterFunc) (map[string][]string, error) {
	searchPaths := filepath.SplitList(ldLibraryPath)
	fallbackSearchPaths := filepath.SplitList(fallbackSearchPath)
	libraries := make(map[string]string)

	// Breadth-first iteration of all the binaries, and their dependencies.
	checkedFile := make(map[string]bool)
	checkedLib := make(map[string]bool)
	toCheck := binaries
	for {
		newToCheck := make(map[string]bool)
		if len(toCheck) == 0 {
			break
		}
		for _, fn := range toCheck {
			if filterFn != nil {
				if err := filterFn(fn); err != nil {
					return nil, err
				}
			}

			impLibs, err := getLibraries(fn)
			if err != nil {
				return nil, err
			}
			debugf("dynlib: %v imports: %v", fn, impLibs)
			checkedFile[fn] = true

			// The internal libraries also need recursive resolution,
			// so just append them to the first binary.
			if extraLibs != nil {
				debugf("dynlib: Appending extra libs: %v", extraLibs)
				impLibs = append(impLibs, extraLibs...)
				extraLibs = nil
			}

			for _, lib := range impLibs {
				if checkedLib[lib] {
					continue
				}

				if isIgnoredLib(lib) {
					continue
				}

				isInPath := func(l string, p []string) string {
					for _, d := range p {
						maybePath := filepath.Join(d, l)
						if fileExists(maybePath) {
							return maybePath
						}
					}
					return ""
				}

				// Look for the library in the various places.
				var libPath string
				var inLdLibraryPath, inCache, inFallbackPath bool
				if libPath = isInPath(lib, searchPaths); libPath != "" {
					inLdLibraryPath = true
				} else if libPath = c.GetLibraryPath(lib); libPath != "" {
					inCache = true
				} else if libPath = isInPath(lib, fallbackSearchPaths); libPath != "" {
					inFallbackPath = true
				} else {
					return nil, fmt.Errorf("dynlib: Failed to find library: %v", lib)
				}

				var libSrc string
				switch {
				case inLdLibraryPath:
					libSrc = "LD_LIBRARY_PATH"
				case inCache:
					libSrc = "ld.so.conf"
				case inFallbackPath:
					libSrc = "Filesystem"
				}
				debugf("dynlib: Found %v (%v).", lib, libSrc)

				// Register the library, assuming it's not in what will
				// presumably be `LD_LIBRARY_PATH` inside the hugbox.
				if !inLdLibraryPath {
					libraries[lib] = libPath
				}
				checkedLib[lib] = true

				if !checkedFile[libPath] {
					newToCheck[libPath] = true
				}
			}
		}
		toCheck = []string{}
		for k := range newToCheck {
			toCheck = append(toCheck, k)
		}
	}

	// De-dup the libraries map by figuring out what can be symlinked.
	ret := make(map[string][]string)
	for lib, fn := range libraries {
		f, err := filepath.EvalSymlinks(fn)
		if err != nil {
			return nil, err
		}

		vec := ret[f]
		vec = append(vec, lib)
		ret[f] = vec
	}

	// XXX: This should sanity check to ensure that aliases are distinct.

	return ret, nil
}

type cacheEntry struct {
	key, value string
	flags      uint32
	osVersion  uint32
	hwcap      uint64
}

type cacheEntries []*cacheEntry

func (e cacheEntries) Len() int {
	return len(e)
}

func (e cacheEntries) Less(i, j int) bool {
	// Bigger hwcap should come first.
	if e[i].hwcap > e[j].hwcap {
		return true
	}
	// Bigger osVersion should come first.
	if e[i].osVersion > e[j].osVersion {
		return true
	}

	// Preserve the ordering otherwise.
	return i < j
}

func (e cacheEntries) Swap(i, j int) {
	e[i], e[j] = e[j], e[i]
}

func parseOldLdCache(b []byte) ([]byte, error) {
	const entrySz = 4 + 4 + 4

	// The new format is embedded in the old format, so do some light
	// parsing/validation to get to the new format's header.

	// old_magic
	if !bytes.HasPrefix(b, cacheMagic) {
		return nil, fmt.Errorf("dynlib: ld.so.cache has invalid old_magic")
	}
	off := len(cacheMagic)
	b = b[off:]

	// nlibs
	if len(b) < 4 {
		return nil, fmt.Errorf("dynlib: ld.so.cache truncated (nlibs)")
	}
	nlibs := int(binary.LittleEndian.Uint32(b))
	off += 4
	b = b[4:]

	// libs[nlibs]
	nSkip := entrySz * nlibs
	if len(b) < nSkip {
		return nil, fmt.Errorf("dynlib: ld.so.cache truncated (libs[])")
	}
	off += nSkip
	b = b[nSkip:]

	// new_magic is 8 byte aligned.
	padLen := (((off+8-1)/8)*8 - off)
	if len(b) < padLen {
		return nil, fmt.Errorf("dynlib: ld.so.cache truncated (pad)")
	}
	return b[padLen:], nil
}

func getNewLdCache(b []byte) ([]byte, error) {
	// This is either just the new format, or the old format embedding
	// the new format (under the assumption that no one is using a
	// version of glibc older than 2.2).
	if !bytes.HasPrefix(b, cacheMagicNew) {
		// Probably the old format, try parsing the header to find the
		// embedded new format.
		var err error
		if b, err = parseOldLdCache(b); err != nil {
			return nil, err
		}
		if !bytes.HasPrefix(b, cacheMagicNew) {
			return nil, fmt.Errorf("dynlib: ld.so.cache has invalid new_magic")
		}
	}

	return b, nil
}

// LoadCache creates a new system shared library cache usually by loading
// and parsing the `/etc/ld.so.cache` file.
//
// See `sysdeps/generic/dl-cache.h` in the glibc source tree for details
// regarding the format.
func LoadCache() (*Cache, error) {
	if !IsSupported() {
		return nil, errUnsupported
	}

	// Certain libc implementations totally lack a ld.so.cache.
	_, err := os.Stat(ldSoCache)
	if err != nil {
		if os.IsNotExist(err) {
			return loadCacheFallback()
		}
	}

	return loadCacheGlibc()
}

func loadCacheGlibc() (*Cache, error) {
	const entrySz = 4 + 4 + 4 + 4 + 8

	ourOsVersion, err := GetOsVersion()
	if err != nil {
		return nil, err
	}
	debugf("dynlib: osVersion: %08x", ourOsVersion)

	c := new(Cache)
	c.store = make(map[string]cacheEntries)

	b, err := ioutil.ReadFile(ldSoCache)
	if err != nil {
		return nil, err
	}

	if b, err = getNewLdCache(b); err != nil {
		return nil, err
	}

	stringTable := b

	// new_magic.
	b = b[len(cacheMagicNew):]

	// nlibs, len_strings, unused[].
	if len(b) < 2*4+5*4 {
		return nil, fmt.Errorf("dynlib: ld.so.cache truncated (new header)")
	}
	nlibs := int(binary.LittleEndian.Uint32(b))
	b = b[4:]
	lenStrings := int(binary.LittleEndian.Uint32(b))
	b = b[4+20:] // Also skip unused[].
	rawLibs := b[:nlibs*entrySz]
	b = b[len(rawLibs):]
	if len(b) < lenStrings {
		// This used to check that len(b) == lenStrings, but that was
		// always not quite the right way to do it, and the file format
		// allows for data after the string table.
		return nil, fmt.Errorf("dynlib: lenStrings appears invalid")
	}

	getString := func(idx int) (string, error) {
		if idx < 0 || idx > len(stringTable) {
			return "", fmt.Errorf("dynlib: string table index out of bounds")
		}
		l := bytes.IndexByte(stringTable[idx:], 0)
		if l == 0 {
			return "", nil
		}
		return string(stringTable[idx : idx+l]), nil
	}

	// libs[]
	var flagCheckFn func(uint32) bool
	switch runtime.GOARCH {
	case archAmd64:
		flagCheckFn = func(flags uint32) bool {
			const wantFlags = flagX8664Lib64 | flagElfLibc6
			return flags&wantFlags == wantFlags
		}
		// HWCAP is unused on amd64.
	default:
		return nil, errUnsupported
	}

	for i := 0; i < nlibs; i++ {
		rawE := rawLibs[entrySz*i : entrySz*(i+1)]

		e := new(cacheEntry)
		e.flags = binary.LittleEndian.Uint32(rawE[0:])
		kIdx := int(binary.LittleEndian.Uint32(rawE[4:])) // nolint: revive
		vIdx := int(binary.LittleEndian.Uint32(rawE[8:]))
		e.osVersion = binary.LittleEndian.Uint32(rawE[12:])
		e.hwcap = binary.LittleEndian.Uint64(rawE[16:])

		e.key, err = getString(kIdx)
		if err != nil {
			return nil, fmt.Errorf("dynlib: failed to query key: %v", err)
		}
		e.value, err = getString(vIdx)
		if err != nil {
			return nil, fmt.Errorf("dynlib: failed to query value: %v", err)
		}

		// Discard libraries we have no hope of using, either due to
		// osVersion, or hwcap.
		if ourOsVersion < e.osVersion {
			debugf("dynlib: ignoring library: %v (osVersion: %x)", e.key, e.osVersion)
		} else if err = ValidateLibraryClass(e.value); err != nil {
			debugf("dynlib: ignoring library %v (%v)", e.key, err)
		} else if flagCheckFn(e.flags) {
			vec := c.store[e.key]
			vec = append(vec, e)
			c.store[e.key] = vec
		} else {
			debugf("dynlib: ignoring library: %v (flags: %x, hwcap: %x)", e.key, e.flags, e.hwcap)
		}
	}

	for lib, entries := range c.store {
		if len(entries) == 1 {
			continue
		}

		// Sort the entires in order of prefernce similar to what ld-linux.so
		// will do.
		sort.Sort(entries)
		c.store[lib] = entries

		paths := []string{}
		for _, e := range entries {
			paths = append(paths, e.value)
		}

		debugf("dynlib: debug: Multiple entry: %v: %v", lib, paths)
	}

	return c, nil
}

func loadCacheFallback() (*Cache, error) {
	c := new(Cache)
	c.store = make(map[string]cacheEntries)

	// The only reason this exists is because some people think that using
	// musl-libc is a good idea, so it is tailored for such systems.
	machine, searchPaths, err := archDepsMusl()
	if err != nil {
		return nil, err
	}

	for _, path := range searchPaths {
		fis, err := ioutil.ReadDir(path)
		if err != nil {
			debugf("dynlib: failed to read directory '%v': %v", path, err)
			continue
		}

		for _, v := range fis {
			// Skip directories.
			if v.IsDir() {
				continue
			}

			fn := filepath.Join(path, v.Name())
			soname, err := getSoname(fn, machine)
			if err != nil {
				debugf("dynlib: ignoring file '%v': %v", fn, err)
				continue
			}

			e := &cacheEntry{
				key:   soname,
				value: fn,
			}

			vec := c.store[e.key]
			vec = append(vec, e)
			c.store[e.key] = vec
		}
	}

	return c, nil
}

func getSoname(path string, machine elf.Machine) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if f.Machine != machine {
		return "", fmt.Errorf("machine mismatch (%v)", f.Machine)
	}

	soNames, err := f.DynString(elf.DT_SONAME)
	if err != nil {
		return "", err
	}
	if len(soNames) < 1 {
		return "", fmt.Errorf("no DT_SONAME entry")
	}

	return soNames[0], nil
}

func archDepsMusl() (elf.Machine, []string, error) {
	var (
		pathFile  string
		machine   elf.Machine
		archPaths []string
	)

	switch runtime.GOARCH {
	case archAmd64:
		machine = elf.EM_X86_64
		pathFile = "/etc/ld-musl-x86_64.path"
		archPaths = []string{
			"/lib64",
			"/usr/lib64",
			"/usr/lib/x86_64-linux-gnu",
			"/lib/x86_64-linux-gnu", // Devuan (and others)
		}
	default:
		return elf.EM_NONE, nil, errUnsupported
	}

	// Try to load `/etc/ld-musl-{LDSO_ARCH}.path`.
	b, err := ioutil.ReadFile(pathFile)
	switch err {
	case nil:
		return machine, strings.FieldsFunc(string(b), func(c rune) bool {
			return c == '\n' || c == ':'
		}), nil
	default:
		debugf("dynlib: failed to read '%v': %v", pathFile, err)
	}

	searchPaths := []string{
		// musl's default library search paths.
		"/lib",
		"/usr/local/lib",
		"/usr/lib",
	}
	searchPaths = append(searchPaths, archPaths...)

	return machine, searchPaths, nil
}

func fileExists(f string) bool {
	if _, err := os.Lstat(f); err != nil && os.IsNotExist(err) {
		// This might be an EPERM, but bubblewrap can have elevated privs,
		// so this may succeed.  If it doesn't, the error will be caught
		// later.
		return false
	}
	return true
}

// isIgnoredLib checks whether the library should be ignored during resolution.
func isIgnoredLib(lib string) bool {
	switch lib {
	case "linux-vdso.so.1":
		// Not a real library. (We only support the x86-64 variant).
		return true
	default:
		return false
	}
}

func debugf(fmt string, args ...interface{}) {
	if Debugf != nil {
		Debugf(fmt, args...)
	}
}
