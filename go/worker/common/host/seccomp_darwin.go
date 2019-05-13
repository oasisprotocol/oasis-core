package host

import (
	"os"

	"github.com/pkg/errors"
)

func generateSeccompPolicy(out *os.File) error {
	return errors.New("seccomp policy not implemented for darwin")
}
