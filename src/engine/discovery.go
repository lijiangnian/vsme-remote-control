package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Addresses are hints, never identities. Every connection still checks the
// original certificate pin before sending credentials or accepting work.
type addressRecord struct {
	Pin      string `json:"pin"`
	Manual   string `json:"manual,omitempty"`
	Verified string `json:"verified,omitempty"`
}
type addressBook struct {
	mu            sync.Mutex
	path          string
	records       map[string]addressRecord
	lastScan      map[string]time.Time
	lastDirectory map[string]time.Time
	directory     map[string]addressPayload
}

func newAddressBook(root string) *addressBook {
	b := &addressBook{path: filepath.Join(root, "controller-addresses.json"), records: map[string]addressRecord{}, lastScan: map[string]time.Time{}, lastDirectory: map[string]time.Time{}, directory: map[string]addressPayload{}}
	if data, err := os.ReadFile(b.path); err == nil && len(data) <= 16384 {
		_ = json.Unmarshal(data, &b.records)
	}
	if b.records == nil {
		b.records = map[string]addressRecord{}
	}
	return b
}

func privateControllerURL(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Port() != "45842" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && ip.To4() != nil && ip.IsPrivate()
}

func (b *addressBook) candidates(p Profile) []Invite {
	if len(p.Invites) == 0 {
		return nil
	}
	b.mu.Lock()
	r := b.records[strings.ToUpper(p.Name)]
	d := b.directory[strings.ToUpper(p.Name)]
	b.mu.Unlock()
	out := []Invite{}
	seen := map[string]bool{}
	add := func(in Invite) {
		if !seen[in.URL] {
			seen[in.URL] = true
			out = append(out, in)
		}
	}
	if d.Pin == p.Invites[0].Pin && d.Expires > time.Now().UnixMilli() {
		for _, ip := range d.IPs {
			in := p.Invites[0]
			in.URL = "https://" + ip + ":45842"
			add(in)
		}
	}
	if r.Pin == p.Invites[0].Pin {
		for _, address := range []string{r.Manual, r.Verified} {
			if privateControllerURL(address) {
				in := p.Invites[0]
				in.URL = address
				add(in)
			}
		}
	}
	for _, in := range p.Invites {
		add(in)
	}
	return out
}

func (b *addressBook) remember(p Profile, address string) {
	if len(p.Invites) == 0 || !privateControllerURL(address) {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	name := strings.ToUpper(p.Name)
	r := b.records[name]
	if r.Pin != p.Invites[0].Pin {
		r = addressRecord{Pin: p.Invites[0].Pin}
	}
	if r.Verified == address {
		return
	}
	r.Verified = address
	b.records[name] = r
	_ = writeJSON(b.path, b.records)
}

func (b *addressBook) manual(p Profile, ipText string) error {
	return b.manualMany([]addressChange{{p, ipText}})
}

type addressChange struct {
	profile Profile
	ip      string
}

func (b *addressBook) manualMany(changes []addressChange) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	next := map[string]addressRecord{}
	for name, record := range b.records {
		next[name] = record
	}
	for _, change := range changes {
		p, ipText := change.profile, strings.TrimSpace(change.ip)
		ip := net.ParseIP(ipText)
		if len(p.Invites) == 0 || (ipText != "" && (ip == nil || ip.To4() == nil || !ip.IsPrivate())) {
			return errors.New("请输入主控当前的局域网 IPv4 地址，例如 10.77.0.14；不要填写用户名、网址或公网地址")
		}
		name := strings.ToUpper(p.Name)
		r := next[name]
		if r.Pin != p.Invites[0].Pin {
			r = addressRecord{Pin: p.Invites[0].Pin}
		}
		r.Manual = ""
		if ipText != "" {
			r.Manual = "https://" + ip.String() + ":45842"
		}
		next[name] = r
	}
	if err := writeJSON(b.path, next); err != nil {
		return err
	}
	b.records = next
	for _, change := range changes {
		delete(b.lastScan, strings.ToUpper(change.profile.Name))
	}
	return nil
}

// Only known controller /24 ranges and at most one additional local /24 are
// searched. Never scan the Internet, a /16, or other service ports.
func discoveryTargets(invites []Invite, local []string) []string {
	prefixes := []string{}
	seen := map[string]bool{}
	add := func(host string) {
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() == nil || !ip.IsPrivate() {
			return
		}
		v := ip.To4()
		prefix := fmt.Sprintf("%d.%d.%d.", v[0], v[1], v[2])
		if !seen[prefix] && len(prefixes) < 2 {
			seen[prefix] = true
			prefixes = append(prefixes, prefix)
		}
	}
	for _, in := range invites {
		if u, err := url.Parse(in.URL); err == nil && privateControllerURL(in.URL) {
			add(u.Hostname())
		}
	}
	// Loopback/custom-port test profiles do not cause real LAN discovery.
	if len(prefixes) == 0 {
		return nil
	}
	for _, ip := range local {
		add(ip)
	}
	out := []string{}
	for _, prefix := range prefixes {
		for n := 1; n < 255; n++ {
			out = append(out, fmt.Sprintf("https://%s%d:45842", prefix, n))
		}
	}
	return out
}

func probePinned(ctx context.Context, in Invite) bool {
	u, err := url.Parse(in.URL)
	if err != nil {
		return false
	}
	client := pinnedClient(in.Pin)
	defer client.CloseIdleConnections()
	// No HTTP authorization, join, command, or enrollment is sent during discovery.
	tr := client.Transport.(*http.Transport)
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 550 * time.Millisecond}, Config: tr.TLSClientConfig.Clone()}
	conn, err := dialer.DialContext(ctx, "tcp4", u.Host)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (b *addressBook) discover(ctx context.Context, p Profile) string {
	if len(p.Invites) == 0 {
		return ""
	}
	b.mu.Lock()
	name := strings.ToUpper(p.Name)
	if time.Since(b.lastScan[name]) < 90*time.Second {
		b.mu.Unlock()
		return ""
	}
	b.lastScan[name] = time.Now()
	b.mu.Unlock()
	targets := discoveryTargets(append(append([]Invite{}, p.Invites...), b.candidates(p)...), localIPs())
	address := scanPinned(ctx, p.Invites[0], targets)
	if address != "" {
		b.remember(p, address)
	}
	return address
}

func scanPinned(parent context.Context, anchor Invite, targets []string) string {
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	queue := make(chan string)
	found := make(chan string, 1)
	var workers sync.WaitGroup
	for n := 0; n < 16; n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for address := range queue {
				if ctx.Err() != nil {
					return
				}
				in := anchor
				in.URL = address
				attempt, stop := context.WithTimeout(ctx, 550*time.Millisecond)
				ok := probePinned(attempt, in)
				stop()
				if ok {
					select {
					case found <- address:
					default:
					}
					cancel()
					return
				}
			}
		}()
	}
	go func() {
		defer close(queue)
		for _, target := range targets {
			select {
			case queue <- target:
			case <-ctx.Done():
				return
			}
		}
	}()
	workers.Wait()
	select {
	case address := <-found:
		return address
	default:
		return ""
	}
}

func (a *App) setControllerAddress(name, ip string) error {
	return a.setControllerAddresses([]addressShare{{Name: name, IPs: []string{ip}}})
}
func (a *App) setControllerAddresses(shares []addressShare) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	changes := []addressChange{}
	agents := []*Agent{}
	for _, share := range shares {
		if a.hub != nil && strings.EqualFold(share.Name, machine().Name) {
			continue
		}
		var ag *Agent
		for _, candidate := range a.agents {
			if candidate.profile != nil && strings.EqualFold(candidate.profile.Name, share.Name) {
				ag = candidate
				break
			}
		}
		if ag == nil || len(share.IPs) == 0 {
			return errors.New("请选择本机正在连接的指定主控：CONTROL-A 或 CONTROL-B")
		}
		st := ag.snapshot()
		if st.Active != "" {
			return fmt.Errorf("%s 正在执行任务，请等完成后再更新地址", share.Name)
		}
		if st.State == "closed" && strings.Contains(st.Error, "HTTP 403") {
			return errors.New("本次授权已明确撤销，请在副机重新打开软件")
		}
		changes = append(changes, addressChange{*ag.profile, share.IPs[0]})
		agents = append(agents, ag)
	}
	if len(changes) == 0 {
		return errors.New("分享内容中没有其他主控地址")
	}
	if err := a.engine.addresses.manualMany(changes); err != nil {
		return err
	}
	for i, ag := range agents {
		a.engine.audit.log("controller-address-updated", map[string]string{"controller": changes[i].profile.Name, "ip": changes[i].ip})
		ag.stop()
	}
	return nil
}
