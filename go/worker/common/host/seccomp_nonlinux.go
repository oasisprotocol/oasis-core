// +build !linux

package host

import (
	"os"

	"github.com/pkg/errors"
)

func generateSeccompPolicy(out *os.File) error {
	return errors.New("generateSeccompPolicy only implemented for Linux")
}
