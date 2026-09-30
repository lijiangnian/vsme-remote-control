//go:build darwin

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// Do not allow a detached process or /dev/null to masquerade as an open
// authorization window. Terminal EOF/HUP and explicit Stop end the session.
func terminalAttached() bool {
	var settings syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, os.Stdin.Fd(), syscall.TIOCGETA, uintptr(unsafe.Pointer(&settings)))
	return errno == 0
}
