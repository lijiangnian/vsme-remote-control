package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Deployment configuration is private and is never embedded into public binaries.

type Identity struct {
	Certificate []byte `json:"certificate"`
	PrivateKey  []byte `json:"private_key"`
	JoinKey     string `json:"join_key"`
}

func identity(root string) (tls.Certificate, string, string, error) {
	path := filepath.Join(root, "identity.json")
	var v Identity
	b, e := os.ReadFile(path)
	if e == nil {
		if e = json.Unmarshal(b, &v); e != nil {
			return tls.Certificate{}, "", "", e
		}
		k, e := x509.ParsePKCS8PrivateKey(v.PrivateKey)
		if e != nil {
			return tls.Certificate{}, "", "", e
		}
		h := sha256.Sum256(v.Certificate)
		return tls.Certificate{Certificate: [][]byte{v.Certificate}, PrivateKey: k}, hex.EncodeToString(h[:]), v.JoinKey, nil
	}
	if !os.IsNotExist(e) {
		return tls.Certificate{}, "", "", e
	}
	c, p, e := certificate()
	if e != nil {
		return c, "", "", e
	}
	k, e := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if e != nil {
		return c, "", "", e
	}
	v = Identity{c.Certificate[0], k, token()}
	if e = writeJSON(path, v); e != nil {
		return c, "", "", e
	}
	return c, p, v.JoinKey, nil
}

type Profile struct {
	Name    string   `json:"name"`
	Invites []Invite `json:"invites"`
}

func loadFleet(path string) ([]Profile, error) {
	if path == "" {
		path = filepath.Join(dataRoot(), "fleet.json")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var v []Profile
	if e = json.Unmarshal(b, &v); e != nil {
		return nil, e
	}
	if len(v) != 2 {
		return nil, errors.New("配置需要两台指定控制电脑")
	}
	seen := map[string]bool{}
	for _, p := range v {
		name := strings.ToUpper(p.Name)
		if name == "" || !validMonitor(name, 45842) || seen[name] || len(p.Invites) == 0 {
			return nil, errors.New("只能配置已指定的两台控制端")
		}
		seen[name] = true
		for _, in := range p.Invites {
			if in.Pin != p.Invites[0].Pin || in.Key != p.Invites[0].Key {
				return nil, errors.New("同一主控的备用地址必须使用相同证书与接入身份")
			}
			u, err := url.Parse(in.URL)
			pin, hexErr := hex.DecodeString(in.Pin)
			if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || hexErr != nil || len(pin) != 32 || len(in.Key) < 32 {
				return nil, errors.New("控制端连接配置无效")
			}
		}
	}
	return v, nil
}
