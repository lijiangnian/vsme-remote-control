package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

var version = "2.1.2.0"

const lease = 20 * time.Second
const maxFile = int64(2 << 30)

var defaultRole = "controller"

type Machine struct {
	Name    string   `json:"name"`
	OS      string   `json:"os"`
	Arch    string   `json:"arch"`
	User    string   `json:"user"`
	Admin   bool     `json:"admin"`
	IPs     []string `json:"ips"`
	Version string   `json:"version"`
	Note    string   `json:"note"`
}

func machine() Machine {
	n, _ := os.Hostname()
	u, _ := user.Current()
	name := ""
	if u != nil {
		name = u.Username
	}
	if runtime.GOOS == "darwin" && os.Getenv("SUDO_USER") != "" && isAdmin() {
		name = os.Getenv("SUDO_USER") + " (sudo root)"
	}
	return Machine{Name: n, OS: runtime.GOOS, Arch: runtime.GOARCH, User: name, Admin: isAdmin(), IPs: localIPs(), Version: version}
}
func localIPs() []string {
	out := []string{}
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 {
			continue
		}
		as, _ := i.Addrs()
		for _, a := range as {
			ip, _, _ := net.ParseCIDR(a.String())
			if ip != nil && ip.To4() != nil && !ip.IsLoopback() && ip.IsPrivate() {
				out = append(out, ip.String())
			}
		}
	}
	return out
}
func token() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func same(a, b string) bool { return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func hashFile(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	_, e = io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), e
}
func dataRoot() string { d, _ := os.UserConfigDir(); return filepath.Join(d, "VSME-RemoteControl-OSS") }
func privateDir(path string) error {
	if e := os.MkdirAll(path, 0700); e != nil {
		return e
	}
	return protectDir(path)
}
func writeJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, b, 0600)
}
func decode(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}
func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, e error) {
	w.WriteHeader(http.StatusBadRequest)
	reply(w, map[string]string{"error": e.Error()})
}
func localOnly(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(host)
		if ip == nil || !(ip.IsLoopback() || ip.IsPrivate()) {
			http.Error(w, "Private network only", 403)
			return
		}
		h.ServeHTTP(w, r)
	})
}
func certificate() (tls.Certificate, string, error) {
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return tls.Certificate{}, "", e
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	t := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "CONTROL-A Repair controller"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(5, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, t, t, &k.PublicKey, k)
	if e != nil {
		return tls.Certificate{}, "", e
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, hex.EncodeToString(sum[:]), nil
}

type Invite struct {
	URL string `json:"url"`
	Pin string `json:"pin"`
	Key string `json:"key"`
}

func (i Invite) String() string {
	b, _ := json.Marshal(i)
	return "CONTROL-A2-" + base64.RawURLEncoding.EncodeToString(b)
}
func parseInvite(s string) (Invite, error) {
	var i Invite
	b, e := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), "CONTROL-A2-"))
	if e == nil {
		e = json.Unmarshal(b, &i)
	}
	if e != nil || len(i.Pin) != 64 || len(i.Key) < 32 || !strings.HasPrefix(i.URL, "https://") {
		return i, errors.New("连接码无效，请复制 CONTROL-A 控制端本次生成的完整连接码")
	}
	return i, nil
}
func pinnedClient(pin string) *http.Client {
	return &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(r *http.Request, v []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("missing server certificate")
		}
		h := sha256.Sum256(cs.PeerCertificates[0].Raw)
		if !same(hex.EncodeToString(h[:]), pin) {
			return errors.New("CONTROL-A 证书指纹不匹配，请重新获取连接码")
		}
		return nil
	}}}}
}
func post(ctx context.Context, c *http.Client, url, key string, in, out any) error {
	b, e := json.Marshal(in)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, e := c.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
	}
	return nil
}

type Job struct {
	ID           string    `json:"id"`
	Agent        string    `json:"agent"`
	Op           string    `json:"op"`
	Command      string    `json:"command"`
	Path         string    `json:"path"`
	Name         string    `json:"name"`
	Size         int64     `json:"size"`
	Hash         string    `json:"hash"`
	State        string    `json:"state"`
	Output       string    `json:"output"`
	Exit         int       `json:"exit"`
	Progress     int64     `json:"progress"`
	Seq          int64     `json:"seq"`
	Created      time.Time `json:"created"`
	Cancel       bool      `json:"cancel"`
	LocalPath    string    `json:"-"`
	DownloadPath string    `json:"-"`
}
type Event struct {
	ID       string `json:"id"`
	Seq      int64  `json:"seq"`
	Output   string `json:"output"`
	State    string `json:"state"`
	Exit     int    `json:"exit"`
	Progress int64  `json:"progress"`
	Path     string `json:"path"`
	Hash     string `json:"hash"`
	Size     int64  `json:"size"`
}
type Poll struct {
	Active string `json:"active"`
}
type Delivery struct {
	Job     *Job   `json:"job"`
	Cancel  string `json:"cancel"`
	Revoked bool   `json:"revoked"`
}
type Audit struct {
	mu sync.Mutex
	f  *os.File
}

func auditOpen(dir string) *Audit {
	os.MkdirAll(dir, 0700)
	f, _ := os.OpenFile(filepath.Join(dir, "audit-"+time.Now().Format("2006-01-02")+".jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	return &Audit{f: f}
}
func (a *Audit) log(action string, v any) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f != nil {
		json.NewEncoder(a.f).Encode(map[string]any{"time": time.Now(), "action": action, "detail": v})
	}
}
func (a *Audit) close() {
	if a != nil {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.f != nil {
			a.f.Close()
			a.f = nil
		}
	}
}
