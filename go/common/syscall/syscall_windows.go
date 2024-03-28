// Package syscall defines OS-specific syscall parameters.
package syscall

import "syscall"

// CmdAttrs is the SysProcAttr used for spawning child processes. It is empty
// for Windows as PR_SET_PDEATH_SIG is not implemented. As a consequence, child
// processes may not be cleaned up.
var CmdAttrs = &syscall.SysProcAttr{}
