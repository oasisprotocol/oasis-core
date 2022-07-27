//go:build linux
// +build linux

package process

import (
	"os"
	"syscall"

	seccomp "github.com/seccomp/libseccomp-golang"

	"github.com/oasisprotocol/oasis-core/go/common/dynlib"
)

// A list of syscalls allowed with any arguments.
// TODO: We can likely reduce this list.
var syscallAllArgsWhitelist = []string{
	"accept",
	"accept4",
	"access",
	"adjtimex",
	"alarm",
	"bind",
	"brk",
	"capget",
	"capset",
	"chdir",
	"chmod",
	"chown",
	"chown32",
	"clock_getres",
	"clock_gettime",
	"clock_nanosleep",
	"close",
	"connect",
	"copy_file_range",
	"creat",
	"dup",
	"dup2",
	"dup3",
	"epoll_create",
	"epoll_create1",
	"epoll_ctl",
	"epoll_ctl_old",
	"epoll_pwait",
	"epoll_wait",
	"epoll_wait_old",
	"eventfd",
	"eventfd2",
	"execve",
	"execveat",
	"exit",
	"exit_group",
	"faccessat",
	"fadvise64",
	"fadvise64_64",
	"fallocate",
	"fanotify_mark",
	"fchdir",
	"fchmod",
	"fchmodat",
	"fchown",
	"fchown32",
	"fchownat",
	"fcntl",
	"fcntl64",
	"fdatasync",
	"fgetxattr",
	"flistxattr",
	"flock",
	"fork",
	"fremovexattr",
	"fsetxattr",
	"fstat",
	"fstat64",
	"fstatat64",
	"fstatfs",
	"fstatfs64",
	"fsync",
	"ftruncate",
	"ftruncate64",
	"futex",
	"futimesat",
	"getcpu",
	"getcwd",
	"getdents",
	"getdents64",
	"getegid",
	"getegid32",
	"geteuid",
	"geteuid32",
	"getgid",
	"getgid32",
	"getgroups",
	"getgroups32",
	"getitimer",
	"getpeername",
	"getpgid",
	"getpgrp",
	"getpid",
	"getppid",
	"getpriority",
	"getrandom",
	"getresgid",
	"getresgid32",
	"getresuid",
	"getresuid32",
	"getrlimit",
	"get_robust_list",
	"getrusage",
	"getsid",
	"getsockname",
	"getsockopt",
	"get_thread_area",
	"gettid",
	"gettimeofday",
	"getuid",
	"getuid32",
	"getxattr",
	"inotify_add_watch",
	"inotify_init",
	"inotify_init1",
	"inotify_rm_watch",
	"io_cancel",
	"ioctl",
	"io_destroy",
	"io_getevents",
	"ioprio_get",
	"ioprio_set",
	"io_setup",
	"io_submit",
	"ipc",
	"kill",
	"lchown",
	"lchown32",
	"lgetxattr",
	"link",
	"linkat",
	"listen",
	"listxattr",
	"llistxattr",
	"_llseek",
	"lremovexattr",
	"lseek",
	"lsetxattr",
	"lstat",
	"lstat64",
	"madvise",
	"memfd_create",
	"mincore",
	"mkdir",
	"mkdirat",
	"mlock",
	"mlock2",
	"mlockall",
	"mmap",
	"mmap2",
	"mprotect",
	"mq_getsetattr",
	"mq_notify",
	"mq_open",
	"mq_timedreceive",
	"mq_timedsend",
	"mq_unlink",
	"mremap",
	"msgctl",
	"msgget",
	"msgrcv",
	"msgsnd",
	"msync",
	"munlock",
	"munlockall",
	"munmap",
	"nanosleep",
	"newfstatat",
	"_newselect",
	"open",
	"openat",
	"pause",
	"pipe",
	"pipe2",
	"poll",
	"ppoll",
	"prctl",
	"pread64",
	"preadv",
	"prlimit64",
	"pselect6",
	"pwrite64",
	"pwritev",
	"read",
	"readahead",
	"readlink",
	"readlinkat",
	"readv",
	"recv",
	"recvfrom",
	"recvmmsg",
	"recvmsg",
	"remap_file_pages",
	"removexattr",
	"rename",
	"renameat",
	"renameat2",
	"restart_syscall",
	"rmdir",
	"rt_sigaction",
	"rt_sigpending",
	"rt_sigprocmask",
	"rt_sigqueueinfo",
	"rt_sigreturn",
	"rt_sigsuspend",
	"rt_sigtimedwait",
	"rt_tgsigqueueinfo",
	"sched_getaffinity",
	"sched_getattr",
	"sched_getparam",
	"sched_get_priority_max",
	"sched_get_priority_min",
	"sched_getscheduler",
	"sched_rr_get_interval",
	"sched_setaffinity",
	"sched_setattr",
	"sched_setparam",
	"sched_setscheduler",
	"sched_yield",
	"seccomp",
	"select",
	"semctl",
	"semget",
	"semop",
	"semtimedop",
	"send",
	"sendfile",
	"sendfile64",
	"sendmmsg",
	"sendmsg",
	"sendto",
	"setfsgid",
	"setfsgid32",
	"setfsuid",
	"setfsuid32",
	"setgid",
	"setgid32",
	"setgroups",
	"setgroups32",
	"setitimer",
	"setpgid",
	"setpriority",
	"setregid",
	"setregid32",
	"setresgid",
	"setresgid32",
	"setresuid",
	"setresuid32",
	"setreuid",
	"setreuid32",
	"setrlimit",
	"set_robust_list",
	"setsid",
	"setsockopt",
	"set_thread_area",
	"set_tid_address",
	"setuid",
	"setuid32",
	"setxattr",
	"shmat",
	"shmctl",
	"shmdt",
	"shmget",
	"shutdown",
	"sigaltstack",
	"signalfd",
	"signalfd4",
	"sigreturn",
	"socket",
	"socketcall",
	"socketpair",
	"splice",
	"stat",
	"stat64",
	"statfs",
	"statfs64",
	"symlink",
	"symlinkat",
	"sync",
	"sync_file_range",
	"syncfs",
	"sysinfo",
	"tee",
	"tgkill",
	"time",
	"timer_create",
	"timer_delete",
	"timerfd_create",
	"timerfd_gettime",
	"timerfd_settime",
	"timer_getoverrun",
	"timer_gettime",
	"timer_settime",
	"times",
	"tkill",
	"truncate",
	"truncate64",
	"ugetrlimit",
	"umask",
	"uname",
	"unlink",
	"unlinkat",
	"utime",
	"utimensat",
	"utimes",
	"vfork",
	"vmsplice",
	"wait4",
	"waitid",
	"waitpid",
	"write",
	"writev",

	// x86/x86-64 specific.
	"arch_prctl",
	"modify_ldt",
}

// Generate a new worker SECCOMP policy and write it in BPF format to specified
// file descriptor.
func generateSeccompPolicy(out *os.File) error {
	// Create a new filter, disallowing everything by default.
	filter, err := seccomp.NewFilter(seccomp.ActErrno.SetReturnCode(int16(syscall.EPERM)))
	if err != nil {
		return err
	}
	defer filter.Release()

	// Allow all whitelisted calls with any arguments.
	for _, name := range syscallAllArgsWhitelist {
		syscallID, serr := seccomp.GetSyscallFromName(name)
		if serr != nil {
			return serr
		}
		if serr := filter.AddRule(syscallID, seccomp.ActAllow); serr != nil {
			return serr
		}
	}

	// Clone syscall.
	cloneID, err := seccomp.GetSyscallFromName("clone")
	if err != nil {
		return err
	}
	// Disallow clone in a new namespace, otherwise allow.
	err = filter.AddRuleConditional(cloneID, seccomp.ActAllow, []seccomp.ScmpCondition{
		{Argument: 0, Op: seccomp.CompareMaskedEqual, Operand1: 0, Operand2: 0x7c020000},
	})
	if err != nil {
		return err
	}

	// Handle clone3 if the kernel is new enough to support it.
	osVersion, err := dynlib.GetOsVersion()
	if err != nil {
		return err
	}
	if osVersion >= 0x50300 { // "The clone3() system call first appeared in Linux 5.3.""
		if err = handleClone3(filter); err != nil {
			return err
		}
	}

	return filter.ExportBPF(out)
}

func handleClone3(filter *seccomp.ScmpFilter) error {
	// We need to handle the clone3 syscall in a special manner as there are several complications
	// to its handling:
	//
	// - Newer glibc versions will try clone3 first and if they see EPERM they will instantly fail
	//   making the program unable to spawn threads.
	//
	// - The clone3 syscall is much more complex than clone and so we can't simply inspect its flags
	//   as above for clone.
	//
	// Therefore we need to reject the syscall with ENOSYS, causing fallback to clone.
	clone3ID, err := seccomp.GetSyscallFromName("clone3")
	if err != nil {
		return err
	}
	err = filter.AddRule(clone3ID, seccomp.ActErrno.SetReturnCode(int16(syscall.ENOSYS)))
	if err != nil {
		return err
	}
	return nil
}
