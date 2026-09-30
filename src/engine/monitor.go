package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Independent, read-only probes for servers that do not run this application.
// A successful TCP connection is NOT proof of login/repair permission or system health.
type Monitor struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	State     string    `json:"state"`
	Checked   time.Time `json:"checked"`
	LastSeen  time.Time `json:"last_seen"`
	LatencyMS int64     `json:"latency_ms"`
	Error     string    `json:"error"`
}
type MonitorSet struct {
	mu    sync.Mutex
	items []Monitor
	path  string
	ctx   context.Context
}

func validMonitor(host string, port int) bool {
	if host == "" || len(host) > 253 || port < 1 || port > 65535 {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsPrivate() || ip.IsLoopback()
	}
	for _, c := range host {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-') {
			return false
		}
	}
	return true
}
func newMonitors(ctx context.Context, root string) *MonitorSet {
	m := &MonitorSet{ctx: ctx, path: filepath.Join(root, "servers.json"), items: []Monitor{}}
	b, e := os.ReadFile(m.path)
	if e == nil {
		var values []Monitor
		if json.Unmarshal(b, &values) == nil {
			for _, v := range values {
				if v.Host == "10.77.0.12" && v.Port == 22 && strings.HasPrefix(v.Name, "CONTROL-B ·") {
					v.Host = "CONTROL-B"
				}
				if v.Host == "10.77.0.11" && v.Port == 22 && strings.HasPrefix(v.Name, "CONTROL-A ·") {
					v.Host = "CONTROL-A"
				}
				if v.Host == "10.77.0.13" && v.Port == 22 && strings.HasPrefix(v.Name, "VSME") {
					v.Host = "VSME"
				}
				if len(m.items) < 20 && validMonitor(v.Host, v.Port) {
					v.State = "等待检测"
					m.items = append(m.items, v)
				}
			}
		}
	}
	go m.run()
	return m
}
func (m *MonitorSet) snapshot() []Monitor {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Monitor{}, m.items...)
}
func (m *MonitorSet) add(name, host string, port int) error {
	host = strings.TrimSpace(host)
	name = strings.TrimSpace(name)
	if !validMonitor(host, port) || len(name) > 240 {
		return fmt.Errorf("请输入局域网 IP 或电脑名，以及 1–65535 的现有服务端口")
	}
	if name == "" {
		name = host
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.items) >= 20 {
		return fmt.Errorf("最多监测 20 台服务器")
	}
	for _, v := range m.items {
		if strings.EqualFold(v.Host, host) && v.Port == port {
			return fmt.Errorf("该服务已添加")
		}
	}
	m.items = append(m.items, Monitor{ID: token()[:12], Name: name, Host: host, Port: port, State: "等待检测"})
	return writeJSON(m.path, m.items)
}
func (m *MonitorSet) remove(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, v := range m.items {
		if v.ID == id {
			m.items = append(m.items[:i], m.items[i+1:]...)
			return writeJSON(m.path, m.items)
		}
	}
	return fmt.Errorf("记录不存在")
}
func (m *MonitorSet) run() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		values := m.snapshot()
		var wg sync.WaitGroup
		slots := make(chan struct{}, 4)
		for _, v := range values {
			if m.ctx.Err() != nil {
				return
			}
			slots <- struct{}{}
			wg.Add(1)
			go func(v Monitor) {
				defer wg.Done()
				defer func() { <-slots }()
				v = probeMonitor(m.ctx, v)
				m.mu.Lock()
				for i, item := range m.items {
					if item.ID == v.ID {
						m.items[i] = v
						break
					}
				}
				m.mu.Unlock()
			}(v)
		}
		wg.Wait()
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func probeMonitor(parent context.Context, v Monitor) Monitor {
	ctx, cancel := context.WithTimeout(parent, 2500*time.Millisecond)
	defer cancel()
	start := time.Now()
	v.Checked = start
	v.Error = ""
	v.State = "服务不可达"
	ips, e := net.DefaultResolver.LookupIP(ctx, "ip4", v.Host)
	if e != nil {
		for _, address := range directoryIPs(ctx, v.Host) {
			if ip := net.ParseIP(address); ip != nil {
				ips = append(ips, ip)
			}
		}
		if len(ips) > 0 {
			e = nil
		}
	}
	if e != nil {
		v.State = "名称解析失败"
		v.Error = e.Error()
		return v
	}
	for _, ip := range ips {
		if !ip.IsPrivate() && !ip.IsLoopback() {
			v.Error = "只允许检查内网地址"
			continue
		}
		conn, e := (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), strconv.Itoa(v.Port)))
		if e == nil {
			conn.Close()
			v.State = "服务可达"
			v.LastSeen = time.Now()
			v.LatencyMS = time.Since(start).Milliseconds()
			return v
		}
		v.Error = e.Error()
	}
	return v
}
