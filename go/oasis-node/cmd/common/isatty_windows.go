//go:build windows

package common

// Isatty returns true iff the provided file descriptor is a terminal.
func Isatty(fd uintptr) bool {
	return false
}
