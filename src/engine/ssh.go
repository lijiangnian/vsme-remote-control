package main

// Company SSH bindings and private-key paths are intentionally excluded.
// This public candidate does not install or modify any persistent SSH service.
import (
	"context"
	"errors"
	"os/exec"
)

type SSHPeer struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	User     string `json:"user"`
	Verified bool   `json:"identity_verified"`
}

func sshPeers() []SSHPeer { return []SSHPeer{} }
func sshCommand(context.Context, string, string) (*exec.Cmd, error) {
	return nil, errors.New("公开候选版不附带公司常驻 SSH 授权；请使用独立的系统 SSH 配置")
}
func runSSHCLI([]string) error {
	return errors.New("公开候选版未启用常驻 SSH 适配器")
}
