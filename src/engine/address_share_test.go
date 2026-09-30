package main

import (
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func TestDualShareOnePasteAndAtomicValidation(t *testing.T) {
	shares := []addressShare{{Name: "CONTROL-B", IPs: []string{"10.77.0.14"}}, {Name: "CONTROL-A", IPs: []string{"10.77.0.11"}}}
	text := encodeAddressBundle(shares)
	parsed, err := parseAddressBundle("管理员：\n" + text)
	if err != nil || len(parsed) != 2 || parsed[0].IPs[0] != "10.77.0.14" || parsed[1].Name != "CONTROL-A" {
		t.Fatalf("dual parse failed: %+v %v", parsed, err)
	}
	if _, err := parseAddressBundle(encodeAddressBundle([]addressShare{shares[0], shares[0]})); err == nil {
		t.Fatal("duplicate controller accepted")
	}
	app := newApp(t.TempDir(), nil, true)
	for _, share := range shares {
		p := Profile{Name: share.Name, Invites: []Invite{{"https://192.168.0.254:45842", strings.Repeat("a", 64), strings.Repeat("b", 40)}}}
		ag := newAgent(app.ctx, p.Invites[0], app.engine)
		ag.profile = &p
		app.agents = append(app.agents, ag)
	}
	defer func() {
		for _, ag := range app.agents {
			close(ag.done)
		}
		app.close()
	}()
	app.agents[1].Status.Active = "busy"
	if app.setControllerAddresses(parsed) == nil {
		t.Fatal("busy second channel ignored")
	}
	if len(app.engine.addresses.records) != 0 || app.agents[0].ctx.Err() != nil {
		t.Fatal("partial import modified first channel")
	}
	app.agents[1].Status.Active = ""
	if err := app.setControllerAddresses(parsed); err != nil {
		t.Fatal(err)
	}
	if len(app.engine.addresses.records) != 2 {
		t.Fatal("dual address import incomplete")
	}
}

func TestLiveDualControllerShare(t *testing.T) {
	output := os.Getenv("VSME_LIVE_SHARE_OUTPUT")
	if output == "" {
		t.Skip("opt-in real controller certificate check")
	}
	h, _ := testHub(t)
	app := newApp(t.TempDir(), h, true)
	fleet, err := loadFleet("")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range fleet {
		if strings.EqualFold(p.Name, machine().Name) {
			continue
		}
		ag := newAgent(app.ctx, p.Invites[0], app.engine)
		ag.profile = &p
		app.agents = append(app.agents, ag)
	}
	defer func() {
		for _, ag := range app.agents {
			close(ag.done)
		}
		app.close()
	}()
	text, err := app.shareControllerAddresses()
	if err != nil {
		t.Fatal(err)
	}
	shares, err := parseAddressBundle(text)
	if err != nil || len(shares) != 2 {
		t.Fatal("live share validation", err)
	}
	if err := os.WriteFile(output, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("Both controller addresses generated after peer certificate verification: %+v", shares)
}

func TestShareTextWholeChatAutoRecognition(t *testing.T) {
	text := encodeAddressShare("control-b", []string{"172.26.32.1", "10.77.0.14"})
	for _, value := range []string{text, "管理员发来的消息：\n" + text + "\n收到后打开软件", "> " + text} {
		out, err := parseAddressShare(value)
		if err != nil || out.Name != "CONTROL-B" || len(out.IPs) != 2 || !strings.Contains(strings.Join(out.IPs, ","), "10.77.0.14") {
			t.Fatalf("auto recognition: %+v %v", out, err)
		}
	}
	for _, bad := range []string{`{"name":"https://attacker","ips":["192.168.0.1"]}`, `{"name":"CONTROL-A","ips":["8.8.8.8"]}`, `{"name":"CONTROL-A","ips":["10.77.0.11"],"pin":"replacement"}`, `{"name":"CONTROL-A","ips":[]}`, `{"name":"CONTROL-A","ips":["https://10.77.0.11:22"]}`} {
		if _, err := parseAddressShare(addressSharePrefix + base64.RawURLEncoding.EncodeToString([]byte(bad))); err == nil {
			t.Fatal("unsafe share accepted", bad)
		}
	}
	if _, err := parseAddressShare("随便的一段文字"); err == nil {
		t.Fatal("unrelated clipboard accepted")
	}
	if _, err := parseAddressShare(strings.Repeat("x", 17000)); err == nil {
		t.Fatal("oversize input accepted")
	}
}

func TestShareAndImportLocalAPIRoles(t *testing.T) {
	h, _ := testHub(t)
	controller := newApp(t.TempDir(), h, true)
	defer controller.close()
	if err := controller.serve(); err != nil {
		t.Fatal(err)
	}
	var shared map[string]string
	if err := post(context.Background(), pinnedClient(""), controller.url+"/api/share-controller-address", "", Input{Key: controller.key}, &shared); err == nil {
		t.Fatal("unverified second controller must not be advertised as ready")
	}
	guest := newApp(t.TempDir(), nil, true)
	ag := newAgent(guest.ctx, Invite{}, guest.engine)
	p := Profile{Name: "CONTROL-A", Invites: []Invite{{"https://10.77.0.11:45842", strings.Repeat("a", 64), strings.Repeat("b", 40)}}}
	ag.profile = &p
	guest.agents = []*Agent{ag}
	defer func() { close(ag.done); guest.close() }()
	if err := guest.serve(); err != nil {
		t.Fatal(err)
	}
	client := pinnedClient("")
	if err := post(context.Background(), client, guest.url+"/api/share-controller-address", "", Input{Key: guest.key}, nil); err == nil {
		t.Fatal("guest generated controller share")
	}
	text := encodeAddressShare("CONTROL-A", []string{"192.168.0.112"})
	if err := post(context.Background(), client, guest.url+"/api/import-controller-address", "", Input{Key: "wrong", Invite: text}, nil); err == nil {
		t.Fatal("missing local authorization accepted")
	}
	if err := post(context.Background(), client, guest.url+"/api/import-controller-address", "", Input{Key: guest.key, Invite: text}, nil); err != nil {
		t.Fatal(err)
	}
	if guest.engine.addresses.candidates(p)[0].URL != "https://192.168.0.112:45842" {
		t.Fatal("import did not save address")
	}
}
