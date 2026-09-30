package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSignedAddressSecurity(t *testing.T) {
	c, pin, err := certificate()
	if err != nil {
		t.Fatal(err)
	}
	p := Profile{Name: "CONTROL-A", Invites: []Invite{{Pin: pin, Key: token()}}}
	now := time.Now()
	s, err := signAddress(c, "CONTROL-A", []string{"10.77.0.12"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if v, e := verifyAddress(s, p, now); e != nil || v.IPs[0] != "10.77.0.12" {
		t.Fatalf("%+v %v", v, e)
	}
	if _, e := verifyAddress(s, p, now.Add(91*time.Second)); e == nil {
		t.Fatal("expired record accepted")
	}
	q := p
	q.Name = "CONTROL-B"
	if _, e := verifyAddress(s, q, now); e == nil {
		t.Fatal("wrong controller accepted")
	}
	bad := s
	bad.Signature = append([]byte{}, s.Signature...)
	bad.Signature[0] ^= 1
	if _, e := verifyAddress(bad, p, now); e == nil {
		t.Fatal("tampered signature accepted")
	}
	other, _, _ := certificate()
	bad.Certificate = other.Certificate[0]
	if _, e := verifyAddress(bad, p, now); e == nil {
		t.Fatal("substitute cert accepted")
	}
	for _, ips := range [][]string{{"8.8.8.8"}, {"127.0.0.1"}, {"10.77.0.12/path"}} {
		bad, _ := signAddress(c, "CONTROL-A", ips, now)
		if _, e := verifyAddress(bad, p, now); e == nil {
			t.Fatal("unsafe address accepted")
		}
	}
}
func TestDirectoryIPChangeAndFallback(t *testing.T) {
	c, pin, _ := certificate()
	p := Profile{Name: "CONTROL-A", Invites: []Invite{{URL: "https://10.77.0.11:45842", Pin: pin, Key: token()}}}
	s, _ := signAddress(c, "CONTROL-A", []string{"10.77.0.12"}, time.Now())
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+directoryReadToken(p.Invites[0].Key) {
			t.Error("read auth missing")
		}
		json.NewEncoder(w).Encode(s)
	}))
	defer server.Close()
	v, e := fetchAddress(context.Background(), server.Client(), server.URL, p)
	if e != nil {
		t.Fatal(e)
	}
	b := newAddressBook(t.TempDir())
	b.directory["CONTROL-A"] = v
	got := b.candidates(p)
	if got[0].URL != "https://10.77.0.12:45842" || got[0].Pin != pin || got[0].Key != p.Invites[0].Key {
		t.Fatal(got)
	}
	v.Expires = time.Now().Add(-time.Second).UnixMilli()
	b.directory["CONTROL-A"] = v
	if b.candidates(p)[0].URL != p.Invites[0].URL {
		t.Fatal("offline directory blocked LAN fallback")
	}
}
