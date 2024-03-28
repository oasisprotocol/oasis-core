//go:build windows
// +build windows

package common

import (
	"fmt"
	"os"
)

// Mkdir creates a directory iff it does not exist.
func Mkdir(d string) error {
	const permDir = os.FileMode(0o700)

	fi, err := os.Lstat(d)
	if err != nil {
		// Iff the directory does not exist, create it.
		if os.IsNotExist(err) {
			if err = os.MkdirAll(d, permDir); err == nil {
				return nil
			}
		}
		return err
	}

	// Ensure that the existing path is a directory.
	fm := fi.Mode()
	if !fm.IsDir() {
		return fmt.Errorf("common/Mkdir: path '%s' is not a directory", d)
	}

	return nil
}
