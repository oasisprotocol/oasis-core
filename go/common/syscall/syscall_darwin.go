// Package syscall defines OS-specific syscall parameters.
package syscall

import "syscall"

// IoctlTermiosGetAttr is the ioctl that implements termios tcgetattr.
const IoctlTermiosGetAttr = syscall.TIOCGETA

// CmdAttrs is the SysProcAttr used for spawning child processes. It is empty
// for Darwin as PR_SET_PDEATH_SIG is not implemented. As a consequence, child
// processes may not be cleaned up.
var CmdAttrs = &syscall.SysProcAttr{}
