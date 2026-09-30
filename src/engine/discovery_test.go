package main

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryBoundedPrivatePortOnly(t *testing.T) {
	p := Invite{URL: "https://10.77.0.12:45842"}
	targets := discoveryTargets([]Invite{p, {URL: "https://CONTROL-A:45842"}, {URL: "https://8.8.8.8:45842"}}, []string{"192.168.1.63", "10.0.0.1", "172.22.16.1"})
	if len(targets) != 508 {
		t.Fatalf("unbounded or missing ranges: %d", len(targets))
	}
	for _, target := range targets {
		if !privateControllerURL(target) || (!strings.HasPrefix(target, "https://10.77.0.") && !strings.HasPrefix(target, "https://192.168.1.")) {
			t.Fatal(target)
		}
	}
	if len(discoveryTargets([]Invite{{URL: "https://127.0.0.1:12345"}}, []string{"192.168.0.2"})) != 0 {
		t.Fatal("test profiles must not scan real networks")
	}
}

func TestManualAddressAndCachePreserveIdentity(t *testing.T) {
	root := t.TempDir()
	b := newAddressBook(root)
	p := Profile{Name: "CONTROL-A", Invites: []Invite{{"https://10.77.0.11:45842", strings.Repeat("a", 64), strings.Repeat("k", 40)}}}
	for _, bad := range []string{"8.8.8.8", "127.0.0.1", "::1", "CONTROL-A", "Administrator", "https://192.168.0.1:22", "192.168.0.1/24", "169.254.1.1"} {
		if b.manual(p, bad) == nil {
			t.Fatalf("unsafe manual address accepted: %s", bad)
		}
	}
	if err := b.manual(p, "10.77.0.14"); err != nil {
		t.Fatal(err)
	}
	b.remember(p, "https://192.168.0.110:45842")
	loaded := newAddressBook(root)
	in := loaded.candidates(p)
	if len(in) != 3 || in[0].URL != "https://10.77.0.14:45842" {
		t.Fatalf("cache/manual not loaded: %+v", in)
	}
	for _, v := range in {
		if v.Pin != p.Invites[0].Pin || v.Key != p.Invites[0].Key {
			t.Fatal("identity replaced")
		}
	}
	data, _ := os.ReadFile(filepath.Join(root, "controller-addresses.json"))
	if strings.Contains(string(data), p.Invites[0].Key) {
		t.Fatal("enrollment credential should not be copied to cache")
	}
	if err := loaded.manual(p, ""); err != nil {
		t.Fatal(err)
	}
	if loaded.candidates(p)[0].URL != "https://192.168.0.110:45842" {
		t.Fatal("automatic mode should use last verified address")
	}
	changed := p
	changed.Invites = []Invite{{p.Invites[0].URL, strings.Repeat("b", 64), p.Invites[0].Key}}
	if len(loaded.candidates(changed)) != 1 {
		t.Fatal("different certificate reused cached address")
	}
}

func TestDiscoveryVerifiesTLSAndDoesNotEnroll(t *testing.T) {
	h, real := testHub(t)
	other, impostor := testHub(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if found := scanPinned(ctx, real, []string{impostor.URL, real.URL}); found != real.URL {
		t.Fatalf("wrong controller: %s", found)
	}
	if len(h.snapshot()) != 0 || len(other.snapshot()) != 0 {
		t.Fatal("discovery enrolled a device")
	}
	bad := real
	bad.Pin = strings.Repeat("f", 64)
	if probePinned(ctx, bad) {
		t.Fatal("invalid certificate trusted")
	}
	ctx2, stop := context.WithCancel(context.Background())
	stop()
	start := time.Now()
	if scanPinned(ctx2, real, []string{real.URL}) != "" || time.Since(start) > time.Second {
		t.Fatal("cancelled scan did not stop")
	}
}

func TestAddressURLRejectsUnexpectedDestination(t *testing.T) {
	for _, value := range []string{"https://192.168.0.1:22", "http://192.168.0.1:45842", "https://user@192.168.0.1:45842", "https://192.168.0.1:45842/join", "https://192.168.0.1:45842?key=x", "https://192.168.0.1:45842#x", "https://8.8.8.8:45842"} {
		if privateControllerURL(value) {
			t.Fatal(value)
		}
	}
	if !privateControllerURL("https://10.20.30.40:45842") {
		t.Fatal("private URL rejected")
	}
	if u, _ := url.Parse("https://10.20.30.40:45842"); u.Port() != "45842" {
		t.Fatal("unexpected URL semantics")
	}
}

func TestManualCannotBypassRevocationOrInterruptActiveWork(t *testing.T) {
	app := newApp(t.TempDir(), nil, true)
	p := Profile{Name: "CONTROL-A", Invites: []Invite{{"https://10.77.0.11:45842", strings.Repeat("a", 64), strings.Repeat("b", 40)}}}
	ag := newAgent(app.ctx, p.Invites[0], app.engine)
	ag.profile = &p
	app.agents = []*Agent{ag}
	defer func() { close(ag.done); app.close() }()
	ag.Status.State = "closed"
	ag.Status.Error = "HTTP 403: session revoked"
	if app.setControllerAddress("CONTROL-A", "10.77.0.14") == nil {
		t.Fatal("revoked connection reopened")
	}
	ag.Status.State = "connected"
	ag.Status.Error = ""
	ag.Status.Active = "running-job"
	if app.setControllerAddress("CONTROL-A", "10.77.0.14") == nil {
		t.Fatal("active job interrupted")
	}
	ag.Status.Active = ""
	if err := app.setControllerAddress("CONTROL-A", "10.77.0.14"); err != nil {
		t.Fatal(err)
	}
	if ag.ctx.Err() == nil {
		t.Fatal("reconnect not requested")
	}
	if err := app.setControllerAddress("arbitrary-controller", "10.77.0.14"); err == nil {
		t.Fatal("unknown controller accepted")
	}
}
