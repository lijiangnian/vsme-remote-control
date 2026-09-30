//go:build windows

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")

func shutdownSignals() []os.Signal { return []os.Signal{os.Interrupt} }
func lockRoot(root string) (func(), error) {
	p, e := syscall.UTF16PtrFromString(filepath.Join(root, "session.lock"))
	if e != nil {
		return nil, e
	}
	h, e := syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if e != nil {
		return nil, fmt.Errorf("此电脑已打开 v2，请先关闭旧窗口：%w", e)
	}
	return func() { syscall.CloseHandle(h) }, nil
}

var createJob = kernel.NewProc("CreateJobObjectW")
var setJob = kernel.NewProc("SetInformationJobObject")
var assignJob = kernel.NewProc("AssignProcessToJobObject")
var resumeProcess = syscall.NewLazyDLL("ntdll.dll").NewProc("NtResumeProcess")

type basicLimit struct {
	ProcessTime int64
	JobTime     int64
	Flags       uint32
	Min         uintptr
	Max         uintptr
	Active      uint32
	Affinity    uintptr
	Priority    uint32
	Scheduling  uint32
}
type ioCounters struct{ ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes uint64 }
type extendedLimit struct {
	Basic                                          basicLimit
	IO                                             ioCounters
	ProcessMemory, JobMemory, PeakProcess, PeakJob uintptr
}

func isAdmin() bool {
	r, _, _ := syscall.NewLazyDLL("shell32.dll").NewProc("IsUserAnAdmin").Call()
	return r != 0
}
func protectDir(path string) error {
	u, e := user.Current()
	if e != nil {
		return e
	}
	c := exec.Command("icacls.exe", path, "/inheritance:r", "/grant:r", "*"+u.Uid+":(OI)(CI)F", "*S-1-5-18:(OI)(CI)F")
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	b, e := c.CombinedOutput()
	if e != nil {
		return fmt.Errorf("protect settings: %v %s", e, b)
	}
	return nil
}
func shellCommand(ctx context.Context, script string) *exec.Cmd {
	shell := ""
	if p, e := exec.LookPath("pwsh.exe"); e == nil {
		shell = p
	} else {
		p := filepath.Join(os.Getenv("ProgramFiles"), "PowerShell", "7", "pwsh.exe")
		if _, e := os.Stat(p); e == nil {
			shell = p
		}
	}
	if shell == "" {
		shell = filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	}
	script = "$OutputEncoding=[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';if(Get-Variable PSStyle -ErrorAction SilentlyContinue){$PSStyle.OutputRendering='PlainText'};\n" + script
	u := utf16.Encode([]rune(script))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		b[i*2] = byte(v)
		b[i*2+1] = byte(v >> 8)
	}
	return exec.CommandContext(ctx, shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-OutputFormat", "Text", "-EncodedCommand", base64.StdEncoding.EncodeToString(b))
}
func runShell(ctx context.Context, script string, out io.Writer) (int, error) {
	j, _, e := createJob.Call(0, 0)
	if j == 0 {
		return -1, e
	}
	defer syscall.CloseHandle(syscall.Handle(j))
	limit := extendedLimit{}
	limit.Basic.Flags = 0x2000
	ok, _, e := setJob.Call(j, 9, uintptr(unsafe.Pointer(&limit)), unsafe.Sizeof(limit))
	if ok == 0 {
		return -1, e
	}
	cmd := shellCommand(ctx, script)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x4 | 0x08000000, HideWindow: true}
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.WaitDelay = 3 * time.Second
	if e := cmd.Start(); e != nil {
		return -1, e
	}
	p, e := syscall.OpenProcess(0x1F0FFF, false, uint32(cmd.Process.Pid))
	if e != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return -1, e
	}
	defer syscall.CloseHandle(p)
	ok, _, e = assignJob.Call(j, uintptr(p))
	if ok == 0 {
		cmd.Process.Kill()
		cmd.Wait()
		return -1, fmt.Errorf("process tracking failed: %w", e)
	}
	s, _, e := resumeProcess.Call(uintptr(p))
	if s != 0 {
		cmd.Process.Kill()
		cmd.Wait()
		return -1, e
	}
	err := cmd.Wait()
	code := cmd.ProcessState.ExitCode()
	return code, err
}
func infoScript() string {
	return `$os=Get-CimInstance Win32_OperatingSystem;$cs=Get-CimInstance Win32_ComputerSystem;$cpu=Get-CimInstance Win32_Processor|Select-Object -First 1;[ordered]@{Computer=$env:COMPUTERNAME;User=[Security.Principal.WindowsIdentity]::GetCurrent().Name;OS=$os.Caption;Version=$os.Version;CPU=$cpu.Name;MemoryGB=[math]::Round($cs.TotalPhysicalMemory/1GB,1);FreeMemoryGB=[math]::Round($os.FreePhysicalMemory/1MB,1);Boot=$os.LastBootUpTime.ToString('o');IPv4=@(Get-NetIPAddress -AddressFamily IPv4|Select-Object -ExpandProperty IPAddress);Disks=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3'|Select-Object DeviceID,@{n='FreeGB';e={[math]::Round($_.FreeSpace/1GB,1)}},@{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}})}|ConvertTo-Json -Depth 4`
}
func firewall(exe string, port int) (func(), error) {
	name := fmt.Sprintf("CONTROL-ARepairV2-%d", os.Getpid())
	run := func(args ...string) error {
		c := exec.Command("netsh.exe", args...)
		c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		b, e := c.CombinedOutput()
		if e != nil {
			return fmt.Errorf("firewall: %v %s", e, b)
		}
		return nil
	}
	e := run("advfirewall", "firewall", "add", "rule", "name="+name, "dir=in", "action=allow", "program="+exe, "protocol=TCP", fmt.Sprintf("localport=%d", port), "remoteip=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16", "profile=any", "enable=yes")
	return func() { run("advfirewall", "firewall", "delete", "rule", "name="+name) }, e
}
func openBrowser(url string) error {
	p, e := syscall.UTF16PtrFromString("open")
	if e != nil {
		return e
	}
	u, e := syscall.UTF16PtrFromString(url)
	if e != nil {
		return e
	}
	r, _, e := syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW").Call(0, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(u)), 0, 0, 1)
	if r <= 32 {
		return e
	}
	return nil
}
func alert(msg string) {
	m, _ := syscall.UTF16PtrFromString(msg)
	t, _ := syscall.UTF16PtrFromString("CONTROL-A 远程维修 v2")
	syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), 0x30)
}
