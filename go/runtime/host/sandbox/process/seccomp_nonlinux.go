//go:build !linux
// +build !linux

package process

import (
	"errors"
	"os"
)

func generateSeccompPolicy(out *os.File) error {
	return errors.New("generateSeccompPolicy only implemented for Linux")
}
