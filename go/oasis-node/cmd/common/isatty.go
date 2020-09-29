package common

import (
	"syscall"
	"unsafe"

	cmnSyscall "github.com/oasisprotocol/oasis-core/go/common/syscall"
)

// Isatty returns true iff the provided file descriptor is a terminal.
func Isatty(fd uintptr) bool {
	var attrs syscall.Termios

	// This could examine the error more specifically to see if
	// something really strange is going on since we expect it
	// to return 0 or ENOTTY all the time, but, "the messed up
	// thing the user passed in that makes it complain" also
	// is not a tty.
	//
	// And yes, this is the standard way of doing this, see your
	// libc implementation of choice.
	_, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL,
		fd,
		cmnSyscall.IoctlTermiosGetAttr,
		uintptr(unsafe.Pointer(&attrs)),
		0,
		0,
		0,
	)

	return errno == 0
}
