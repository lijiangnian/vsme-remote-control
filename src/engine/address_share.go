package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
)

const addressSharePrefix = "VSME-ADDRESS1:"
const addressBundlePrefix = "VSME-ADDRESS2:"

type addressShare struct {
	Name string   `json:"name"`
	IPs  []string `json:"ips"`
}
type addressBundle struct {
	Controllers []addressShare `json:"controllers"`
}

func encodeAddressBundle(shares []addressShare) string {
	var description strings.Builder
	for _, share := range shares {
		fmt.Fprintf(&description, "%s：%s\n", share.Name, strings.Join(share.IPs, "、"))
	}
	data, _ := json.Marshal(addressBundle{shares})
	return fmt.Sprintf("【VSME 双主控连接信息】\n%s\n%s%s\n\n请复制整段消息，打开 v2.1 被控端，点“一键粘贴并连接”。\n自动识别两台主控，不用选择电脑、不用填写 IP 或端口。\n看到“2/2 主控已连接”才表示两台都能控制。两台主控及被控软件都需保持打开。\n文字不含私钥或接入密钥；始终核验原有主控证书。IP 变化后重新分享即可，不需重新打包。", description.String(), addressBundlePrefix, base64.RawURLEncoding.EncodeToString(data))
}
func parseAddressBundle(text string) ([]addressShare, error) {
	if !strings.Contains(text, addressBundlePrefix) {
		v, e := parseAddressShare(text)
		return []addressShare{v}, e
	}
	if len(text) > 16384 {
		return nil, errors.New("连接文字过长")
	}
	start := strings.Index(text, addressBundlePrefix) + len(addressBundlePrefix)
	fields := strings.Fields(text[start:])
	if len(fields) == 0 {
		return nil, errors.New("连接码为空")
	}
	data, e := base64.RawURLEncoding.DecodeString(strings.Trim(fields[0], "`\"'，。"))
	if e != nil {
		return nil, errors.New("双主控连接码不完整")
	}
	var bundle addressBundle
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if dec.Decode(&bundle) != nil || len(bundle.Controllers) != 2 {
		return nil, errors.New("双主控连接码必须包含两台指定主控")
	}
	seen := map[string]bool{}
	for i, v := range bundle.Controllers {
		raw, _ := json.Marshal(v)
		checked, e := parseAddressShare(addressSharePrefix + base64.RawURLEncoding.EncodeToString(raw))
		if e != nil {
			return nil, e
		}
		if seen[checked.Name] {
			return nil, errors.New("连接码重复了同一台主控")
		}
		seen[checked.Name] = true
		bundle.Controllers[i] = checked
	}
	return bundle.Controllers, nil
}

func (a *App) shareControllerAddresses() (string, error) {
	if a.hub == nil {
		return "", errors.New("仅主控可以生成分享文字")
	}
	ctx, cancel := context.WithTimeout(a.ctx, 8*time.Second)
	defer cancel()
	own := strings.ToUpper(machine().Name)
	// Keep the established ranking for this host's physical/virtual addresses.
	self, e := parseAddressShare(encodeAddressShare(own, localIPs()))
	if e != nil {
		return "", e
	}
	shares := []addressShare{self}
	a.mu.Lock()
	agents := append([]*Agent{}, a.agents...)
	a.mu.Unlock()
	for _, ag := range agents {
		if ag.profile == nil {
			continue
		}
		p := *ag.profile
		if strings.EqualFold(p.Name, own) {
			continue
		}
		candidates := a.engine.addresses.candidates(p)
		if st := ag.snapshot(); st.State == "connected" {
			in := p.Invites[0]
			in.URL = st.Controller
			candidates = append([]Invite{in}, candidates...)
		}
		seen := map[string]bool{}
		verified := ""
		for _, in := range candidates {
			u, err := url.Parse(in.URL)
			if err != nil {
				continue
			}
			lookup, stop := context.WithTimeout(ctx, 600*time.Millisecond)
			addresses, _ := net.DefaultResolver.LookupIPAddr(lookup, u.Hostname())
			stop()
			for _, address := range addresses {
				if address.IP.To4() == nil || !address.IP.IsPrivate() || seen[address.IP.String()] {
					continue
				}
				seen[address.IP.String()] = true
				candidate := in
				candidate.URL = "https://" + address.IP.String() + ":45842"
				attempt, stop := context.WithTimeout(ctx, 550*time.Millisecond)
				ok := probePinned(attempt, candidate)
				stop()
				if ok {
					verified = address.IP.String()
					a.engine.addresses.remember(p, candidate.URL)
					break
				}
			}
			if verified != "" {
				break
			}
		}
		if verified == "" {
			return "", fmt.Errorf("暂时不能核验 %s；请先打开另一台主控并等待连通，再复制双主控文字", p.Name)
		}
		shares = append(shares, addressShare{Name: strings.ToUpper(p.Name), IPs: []string{verified}})
	}
	if len(shares) != 2 {
		return "", errors.New("双主控配置尚未就绪，请稍后重试")
	}
	return encodeAddressBundle(shares), nil
}

func encodeAddressShare(name string, ips []string) string {
	name = strings.ToUpper(name)
	ips = append([]string{}, ips...)
	// Prefer the known upper-router network over virtual adapters in the UI text.
	fleet, _ := loadFleet("")
	rank := func(ip string) int {
		for _, p := range fleet {
			if strings.EqualFold(p.Name, name) {
				for _, target := range discoveryTargets(p.Invites, nil) {
					if target == "https://"+ip+":45842" {
						return 0
					}
				}
			}
		}
		return 1
	}
	sort.SliceStable(ips, func(i, j int) bool { return rank(ips[i]) < rank(ips[j]) })
	data, _ := json.Marshal(addressShare{Name: name, IPs: ips})
	return fmt.Sprintf("【VSME 主控连接信息】\n主控电脑：%s\n当前局域网 IP：%s\n维修端口：45842\n\n%s%s\n\n请复制这整段消息，打开 v2.1 被控端，点“一键粘贴并连接”。不用选主控、认 IP 或填写端口。\n两边的软件都要保持打开。只允许原先授权的两台主控，连接时仍核验证书。\n文字不含私钥；IP 变化后重新分享即可，不用重新打包。", name, strings.Join(ips, "、"), addressSharePrefix, base64.RawURLEncoding.EncodeToString(data))
}

func parseAddressShare(text string) (addressShare, error) {
	var out addressShare
	if len(text) > 16384 {
		return out, errors.New("连接文字过长")
	}
	index := strings.Index(text, addressSharePrefix)
	if index < 0 {
		return out, errors.New("未找到主控连接码，请复制主控端生成的整段文字")
	}
	rest := strings.TrimLeft(text[index+len(addressSharePrefix):], " \t\r\n")
	end := 0
	for end < len(rest) {
		c := rest[end]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			break
		}
		end++
	}
	if end == 0 {
		return out, errors.New("连接码为空")
	}
	data, err := base64.RawURLEncoding.DecodeString(rest[:end])
	if err != nil {
		return out, errors.New("连接码不完整，请重新复制")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&out) != nil {
		return out, errors.New("连接码格式无效")
	}
	out.Name = strings.ToUpper(out.Name)
	if out.Name == "" || !validMonitor(out.Name, 45842) || len(out.IPs) == 0 || len(out.IPs) > 8 {
		return out, errors.New("连接码不是指定主控，或没有有效局域网地址")
	}
	for _, value := range out.IPs {
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() == nil || !ip.IsPrivate() {
			return addressShare{}, errors.New("连接码包含非局域网 IPv4 地址")
		}
	}
	return out, nil
}
