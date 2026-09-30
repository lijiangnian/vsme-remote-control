package main

import (
	"context"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestTerminalOwnerReplacesBrowserLeaseAndStopsOnEOF(t *testing.T) {
	app := newApp(t.TempDir(), nil, false)
	defer app.close()
	app.terminalOwned = true
	app.seenUI = true
	app.lastUI = time.Now().Add(-time.Hour)
	if app.browserLeaseExpired(time.Now()) {
		t.Fatal("background page ended terminal-owned authorization")
	}
	if err := app.serve(); err != nil {
		t.Fatal(err)
	}
	r, w := io.Pipe()
	defer r.Close()
	go app.watchOwnerInput(r)
	if !strings.Contains(app.pageContent(), "const terminalLifecycle=true;") {
		t.Fatal("page lifecycle not synchronized")
	}
	w.Close()
	eventually(t, 2*time.Second, func() bool { return app.ctx.Err() != nil })
	legacy := newApp(t.TempDir(), nil, false)
	defer legacy.close()
	legacy.seenUI = true
	legacy.lastUI = time.Now().Add(-time.Minute)
	if !legacy.browserLeaseExpired(time.Now()) {
		t.Fatal("legacy browser protection removed")
	}
}

func TestTerminalModeExplicitStopStillRevokes(t *testing.T) {
	app := newApp(t.TempDir(), nil, false)
	defer app.close()
	app.terminalOwned = true
	if err := app.serve(); err != nil {
		t.Fatal(err)
	}
	if err := post(context.Background(), pinnedClient(""), app.url+"/api/stop", "", Input{Key: app.key}, nil); err != nil {
		t.Fatal(err)
	}
	eventually(t, time.Second, func() bool { return app.ctx.Err() != nil })
}

func TestExpiredSessionDifferentFromExplicitRevocation(t *testing.T) {
	h, in := testHub(t)
	client := pinnedClient(in.Pin)
	secret := token()
	var welcome Welcome
	if err := post(context.Background(), client, in.URL+"/join", in.Key, Join{machine(), secret}, &welcome); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	h.Peers[welcome.ID].Last = time.Now().Add(-time.Minute)
	h.mu.Unlock()
	eventually(t, 3*time.Second, func() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.Peers[welcome.ID].Expired })
	request := func(path, key string) int {
		r, _ := http.NewRequest("POST", in.URL+path+"?id="+welcome.ID, strings.NewReader(`{}`))
		r.Header.Set("Authorization", "Bearer "+key)
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		return response.StatusCode
	}
	for _, path := range []string{"/poll", "/event", "/blob", "/details"} {
		if request(path, secret) != http.StatusGone {
			t.Fatal("expired lease cannot reconnect", path)
		}
		if request(path, "wrong") != http.StatusForbidden {
			t.Fatal("expired metadata exposed without credential", path)
		}
	}
	h.revoke(welcome.ID)
	if request("/poll", secret) != http.StatusForbidden {
		t.Fatal("explicit revoke bypassed")
	}
}

func TestAgentReconnectsAfterExpiredLease(t *testing.T) {
	h, in := testHub(t)
	app := newApp(t.TempDir(), nil, true)
	defer app.close()
	app.profiles([]Profile{{Name: "CONTROL-A", Invites: []Invite{in}}})
	state := func() AgentStatus { app.mu.Lock(); defer app.mu.Unlock(); return app.agents[0].snapshot() }
	eventually(t, 8*time.Second, func() bool { return state().State == "connected" })
	first := state().ID
	h.mu.Lock()
	h.Peers[first].Revoked = true
	h.Peers[first].Expired = true
	h.mu.Unlock()
	eventually(t, 8*time.Second, func() bool { return state().State == "connected" && state().ID != first })
	h.revoke(state().ID)
	eventually(t, 5*time.Second, func() bool { return state().State == "closed" })
}

func TestDualControllerRepeatedExpiryPreservesOtherConnectionAndTerminalOwner(t *testing.T) {
	h1, in1 := testHub(t)
	h2, in2 := testHub(t)
	hubs := []*Hub{h1, h2}
	app := newApp(t.TempDir(), nil, false)
	closed := false
	defer func() {
		if !closed {
			app.close()
		}
	}()
	app.terminalOwned = true
	// A real running watchdog sees an already stale page, not just a helper call.
	app.seenUI = true
	app.lastUI = time.Now().Add(-time.Hour)
	if err := app.serve(); err != nil {
		t.Fatal(err)
	}
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	go app.watchOwnerInput(r)
	app.profiles([]Profile{
		{Name: "CONTROL-A", Invites: []Invite{in1}},
		{Name: "CONTROL-B", Invites: []Invite{in2}},
	})
	state := func(index int) AgentStatus {
		app.mu.Lock()
		defer app.mu.Unlock()
		return app.agents[index].snapshot()
	}
	eventually(t, 8*time.Second, func() bool {
		return state(0).State == "connected" && state(1).State == "connected"
	})
	for cycle := 0; cycle < 6; cycle++ {
		index := cycle % 2
		other := 1 - index
		previous := state(index).ID
		healthy := state(other).ID
		hub := hubs[index]
		hub.mu.Lock()
		hub.Peers[previous].Revoked = true
		hub.Peers[previous].Expired = true
		hub.mu.Unlock()
		eventually(t, 8*time.Second, func() bool {
			if app.ctx.Err() != nil {
				t.Fatal("stale browser or one controller outage ended terminal authorization")
			}
			if s := state(other); s.State != "connected" || s.ID != healthy {
				t.Fatal("reconnecting one controller disturbed the other connection")
			}
			s := state(index)
			return s.State == "connected" && s.ID != previous
		})
	}
	// An explicit revoke on one controller must remain closed even while the
	// other controller and the terminal's local status page are still active.
	h1.revoke(state(0).ID)
	eventually(t, 5*time.Second, func() bool { return state(0).State == "closed" })
	time.Sleep(2500 * time.Millisecond)
	if state(0).State != "closed" || state(1).State != "connected" || app.ctx.Err() != nil {
		t.Fatal("explicit revocation or independent controller lifetime changed")
	}
	w.Close()
	eventually(t, 2*time.Second, func() bool { return app.ctx.Err() != nil })
	app.close()
	closed = true
	for _, hub := range hubs {
		for _, peer := range hub.snapshot() {
			if !peer.Revoked {
				t.Fatal("terminal closure left a controller session authorized")
			}
		}
	}
}

func TestMacPageRefreshKeepsSessionAndPagehideDoesNotStop(t *testing.T) {
	start := strings.Index(page, "<script>") + len("<script>")
	end := strings.Index(page, "</script>")
	script := strings.Replace(page[start:end], "const terminalLifecycle=false;", "const terminalLifecycle=true;", 1)
	stub := `const assert=require('node:assert/strict'); const nodes={};function el(){return {style:{},dataset:{},value:'',textContent:'',append(){},replaceChildren(){},after(){}}}
global.document={getElementById(id){return nodes[id]||(nodes[id]=el())},createElement:el,querySelectorAll(){return []}};let events={},beacons=0;global.window={addEventListener(name,fn){events[name]=fn}};global.location={hash:'',pathname:'/'};global.history={replaceState(){}};global.sessionStorage={getItem(){return 'saved-local-key'},setItem(){}};global.setInterval=()=>{};Object.defineProperty(global,'navigator',{value:{sendBeacon(){beacons++}},configurable:true});global.fetch=async()=>({ok:true,json:async()=>({role:'agent',machine:{name:'Mac test',user:'test',os:'darwin',ips:[]},connections:[]})});`
	checks := `setImmediate(()=>{try{assert.equal(key,'saved-local-key');events.pagehide();assert.equal(beacons,0);assert.equal(closing,false);nodes.stop.onclick();assert.equal(beacons,1);assert.equal(closing,true);console.log('MAC_LIFECYCLE_PAGE=PASS')}catch(e){console.error(e);process.exitCode=1}});`
	cmd := exec.Command("node")
	cmd.Stdin = strings.NewReader(stub + script + checks)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}
