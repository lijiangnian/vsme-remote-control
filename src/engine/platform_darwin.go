//go:build darwin

package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

func isAdmin() bool                { return os.Geteuid() == 0 }
func protectDir(path string) error { return os.Chmod(path, 0700) }
func shutdownSignals() []os.Signal { return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP} }
func shellCommand(ctx context.Context, script string) *exec.Cmd {
	return exec.CommandContext(ctx, "/bin/zsh", "-f", "-c", script)
}
func lockRoot(root string) (func(), error) {
	f, e := os.OpenFile(filepath.Join(root, "session.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, e
	}
	return func() { f.Close() }, nil
}
func runShell(ctx context.Context, script string, out io.Writer) (int, error) {
	cmd := shellCommand(ctx, script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.WaitDelay = 3 * time.Second
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	if e := cmd.Start(); e != nil {
		return -1, e
	}
	defer syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	err := cmd.Wait()
	return cmd.ProcessState.ExitCode(), err
}
func infoScript() string {
	return `printf 'Computer: '; /bin/hostname; /usr/bin/sw_vers; printf '\nCPU: '; /usr/sbin/sysctl -n machdep.cpu.brand_string; printf '\nMemory bytes: '; /usr/sbin/sysctl -n hw.memsize; printf '\nDisk space:\n'; /bin/df -h /; printf '\nNetwork:\n'; /sbin/ifconfig | /usr/bin/awk '/inet / {print $2}'; printf '\nUser: '; /usr/bin/id; printf '\nUptime:\n'; /usr/bin/uptime`
}
func firewall(exe string, port int) (func(), error) { return func() {}, nil }
func openBrowser(url string) error {
	if os.Geteuid() == 0 && os.Getenv("SUDO_USER") != "" {
		return exec.Command("/usr/bin/sudo", "-u", os.Getenv("SUDO_USER"), "/usr/bin/open", url).Run()
	}
	return exec.Command("/usr/bin/open", url).Run()
}
func alert(msg string) { println(msg) }
