package main

// The public directory supplies signed address hints, not commands or identities.
// LAN TLS certificate pins remain mandatory after discovery.
import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Disabled in the public candidate: no unsolicited external device reporting.
const directoryURL = ""

type addressPayload struct {
	Name    string   `json:"name"`
	Pin     string   `json:"pin"`
	IPs     []string `json:"ips"`
	Issued  int64    `json:"issued_at"`
	Expires int64    `json:"expires_at"`
}
type signedAddress struct {
	Payload     []byte `json:"payload"`
	Certificate []byte `json:"certificate"`
	Signature   []byte `json:"signature"`
}

func directoryReadToken(key string) string {
	h := sha256.Sum256([]byte("VSME-address-read-v1:" + key))
	return hex.EncodeToString(h[:])
}
func signAddress(cert tls.Certificate, name string, ips []string, now time.Time) (signedAddress, error) {
	var out signedAddress
	k, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || k.Curve.Params().BitSize != 256 || len(cert.Certificate) == 0 {
		return out, errors.New("地址上报需要原有 P256 主控身份")
	}
	h := sha256.Sum256(cert.Certificate[0])
	out.Payload, _ = json.Marshal(addressPayload{strings.ToUpper(name), hex.EncodeToString(h[:]), ips, now.UnixMilli(), now.Add(90 * time.Second).UnixMilli()})
	digest := sha256.Sum256(out.Payload)
	r, s, err := ecdsa.Sign(rand.Reader, k, digest[:])
	if err != nil {
		return out, err
	}
	out.Signature = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	out.Certificate = cert.Certificate[0]
	return out, nil
}
func verifyAddress(out signedAddress, p Profile, now time.Time) (addressPayload, error) {
	var v addressPayload
	if len(p.Invites) == 0 || len(out.Payload) > 4096 || len(out.Certificate) > 4096 || len(out.Signature) != 64 {
		return v, errors.New("无效的地址记录")
	}
	h := sha256.Sum256(out.Certificate)
	if hex.EncodeToString(h[:]) != p.Invites[0].Pin {
		return v, errors.New("地址记录设备身份不匹配")
	}
	c, err := x509.ParseCertificate(out.Certificate)
	if err != nil {
		return v, err
	}
	k, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok || k.Curve.Params().BitSize != 256 {
		return v, errors.New("无效签名密钥")
	}
	d := sha256.Sum256(out.Payload)
	if !ecdsa.Verify(k, d[:], new(big.Int).SetBytes(out.Signature[:32]), new(big.Int).SetBytes(out.Signature[32:])) {
		return v, errors.New("地址签名不匹配")
	}
	if err = json.Unmarshal(out.Payload, &v); err != nil {
		return v, err
	}
	ms := now.UnixMilli()
	if !strings.EqualFold(v.Name, p.Name) || v.Pin != p.Invites[0].Pin || v.Issued > ms+10000 || v.Issued < ms-90000 || v.Expires <= ms || v.Expires <= v.Issued || v.Expires-v.Issued > 90000 || len(v.IPs) > 16 {
		return v, errors.New("地址记录已过期或不属于所选主控")
	}
	for _, ip := range v.IPs {
		if !privateControllerURL("https://" + ip + ":45842") {
			return v, errors.New("拒绝非内网 IPv4 地址")
		}
	}
	return v, nil
}
func directoryClient() *http.Client {
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func fetchAddress(ctx context.Context, client *http.Client, base string, p Profile) (addressPayload, error) {
	var v addressPayload
	if len(p.Invites) == 0 {
		return v, errors.New("缺少身份")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/v1/address/"+strings.ToUpper(p.Name), nil)
	if err != nil {
		return v, err
	}
	req.Header.Set("Authorization", "Bearer "+directoryReadToken(p.Invites[0].Key))
	r, err := client.Do(req)
	if err != nil {
		return v, err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return v, fmt.Errorf("地址服务 HTTP %d", r.StatusCode)
	}
	var record signedAddress
	if err = json.NewDecoder(io.LimitReader(r.Body, 16384)).Decode(&record); err != nil {
		return v, err
	}
	return verifyAddress(record, p, time.Now())
}
func (b *addressBook) refreshDirectory(ctx context.Context, p Profile) bool {
	if directoryURL == "" {
		return false
	}
	b.mu.Lock()
	name := strings.ToUpper(p.Name)
	if time.Since(b.lastDirectory[name]) < 15*time.Second {
		b.mu.Unlock()
		return false
	}
	b.lastDirectory[name] = time.Now()
	b.mu.Unlock()
	client := directoryClient()
	defer client.CloseIdleConnections()
	v, err := fetchAddress(ctx, client, directoryURL, p)
	if err != nil {
		return false
	}
	b.mu.Lock()
	b.directory[name] = v
	b.mu.Unlock()
	return len(v.IPs) != 0
}
func (a *App) publishAddresses() {
	if directoryURL == "" {
		return
	}
	if a.hub == nil || a.hub.Listener == nil || !strings.HasSuffix(a.hub.Listener.Addr().String(), ":45842") {
		return
	}
	profiles, err := loadFleet("")
	if err != nil {
		return
	}
	var own *Profile
	for _, p := range profiles {
		if strings.EqualFold(p.Name, machine().Name) && p.Invites[0].Pin == a.hub.pin {
			v := p
			own = &v
		}
	}
	if own == nil {
		return
	} // Never register a replacement controller identity silently.
	client := directoryClient()
	defer client.CloseIdleConnections()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	previous := ""
	last := time.Time{}
	for {
		ips := localIPs()
		encoded, _ := json.Marshal(ips)
		if string(encoded) != previous || time.Since(last) >= 30*time.Second {
			record, err := signAddress(a.hub.cert, own.Name, ips, time.Now())
			if err == nil {
				body, _ := json.Marshal(record)
				req, e := http.NewRequestWithContext(a.ctx, "POST", directoryURL+"/v1/address/"+own.Name, bytes.NewReader(body))
				if e == nil {
					req.Header.Set("Content-Type", "application/json")
					r, e := client.Do(req)
					if e == nil {
						io.Copy(io.Discard, io.LimitReader(r.Body, 16384))
						r.Body.Close()
						if r.StatusCode == 200 {
							if previous != string(encoded) {
								a.engine.audit.log("address-directory-updated", map[string]any{"controller": own.Name, "ips": ips})
							}
							previous, last = string(encoded), time.Now()
						}
					}
				}
			}
		}
		select {
		case <-a.ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Export only public certificate material for directory deployment tooling.
func addressPublicKey(cert []byte) (string, error) {
	c, err := x509.ParseCertificate(cert)
	if err != nil {
		return "", err
	}
	b, err := x509.MarshalPKIXPublicKey(c.PublicKey)
	return base64.StdEncoding.EncodeToString(b), err
}

func directoryIPs(ctx context.Context, name string) []string {
	if directoryURL == "" {
		return nil
	}
	profiles, err := loadFleet("")
	if err != nil {
		return nil
	}
	for _, p := range profiles {
		if strings.EqualFold(p.Name, name) {
			client := directoryClient()
			defer client.CloseIdleConnections()
			v, err := fetchAddress(ctx, client, directoryURL, p)
			if err == nil {
				return v.IPs
			}
		}
	}
	return nil
}
