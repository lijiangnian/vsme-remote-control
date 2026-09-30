package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testHub(t *testing.T) (*Hub, Invite) {
	t.Helper()
	c, p, e := certificate()
	if e != nil {
		t.Fatal(e)
	}
	h := newHub(t.TempDir(), c, p, token(), true)
	if e = h.start("127.0.0.1:0"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(h.close)
	return h, Invite{"https://" + h.Listener.Addr().String(), p, h.key}
}
func eventually(t *testing.T, d time.Duration, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatal("condition timed out after", d)
}
func testAgent(t *testing.T, in Invite, en *Engine) *Agent {
	t.Helper()
	a := newAgent(context.Background(), in, en)
	go a.run()
	t.Cleanup(func() {
		a.stop()
		select {
		case <-a.done:
		case <-time.After(8 * time.Second):
			t.Error("agent did not stop")
		}
	})
	eventually(t, 8*time.Second, func() bool { return a.snapshot().State == "connected" })
	return a
}
func testEngine(t *testing.T) *Engine {
	e := newEngine(t.TempDir())
	t.Cleanup(e.audit.close)
	return e
}
func finished(t *testing.T, h *Hub, a *Agent, j *Job, d time.Duration) *Job {
	t.Helper()
	var v *Job
	eventually(t, d, func() bool {
		v, _ = h.job(a.snapshot().ID, j.ID)
		return v != nil && v.State != "queued" && v.State != "running"
	})
	return v
}
func add(t *testing.T, h *Hub, a *Agent, op, cmd, path string) *Job {
	t.Helper()
	j, e := h.addJob(a.snapshot().ID, op, cmd, path)
	if e != nil {
		t.Fatal(e)
	}
	return j
}

func TestReverseConnectionCommandAndFileRoundTrip(t *testing.T) {
	h, in := testHub(t)
	a := testAgent(t, in, testEngine(t))
	j := add(t, h, a, "shell", "Write-Output '反向连接-中文-OK'; Write-Output $env:COMPUTERNAME", "")
	v := finished(t, h, a, j, 15*time.Second)
	if v.State != "completed" || !strings.Contains(v.Output, "反向连接-中文-OK") {
		t.Fatalf("command: %+v", v)
	}
	// The agent has no listening socket. All tasks/files travel on requests it initiates.
	src := filepath.Join(t.TempDir(), "中文 测试.dat")
	payload := bytes.Repeat([]byte("反向文件\x00\xff"), 100000)
	if e := os.WriteFile(src, payload, 0600); e != nil {
		t.Fatal(e)
	}
	want, _ := hashFile(src)
	put := add(t, h, a, "put", "", src)
	sent := finished(t, h, a, put, 20*time.Second)
	if sent.State != "completed" || sent.Hash != want {
		t.Fatalf("send: %+v", sent)
	}
	got, e := os.ReadFile(sent.Path)
	if e != nil || !bytes.Equal(got, payload) {
		t.Fatal("received bytes mismatch", e)
	}
	get := add(t, h, a, "get", "", sent.Path)
	received := finished(t, h, a, get, 20*time.Second)
	if received.State != "completed" {
		t.Fatalf("get: %+v", received)
	}
	actual, e := hashFile(received.Path)
	if e != nil || actual != want {
		t.Fatal("returned hash/path", e, received.Path)
	}
	info := finished(t, h, a, add(t, h, a, "info", "", ""), 20*time.Second)
	if info.State != "completed" || !strings.Contains(info.Output, "Computer") {
		t.Fatalf("info: %+v", info)
	}
}

func TestAuthenticationAndRoles(t *testing.T) {
	h, in := testHub(t)
	ctx := context.Background()
	bad := pinnedClient(strings.Repeat("0", 64))
	if post(ctx, bad, in.URL+"/join", in.Key, Join{machine(), token()}, nil) == nil {
		t.Fatal("bad TLS pin accepted")
	}
	c := pinnedClient(in.Pin)
	if post(ctx, c, in.URL+"/join", "wrong", Join{machine(), token()}, nil) == nil {
		t.Fatal("bad enrollment accepted")
	}
	a := testAgent(t, in, testEngine(t))
	if post(ctx, c, in.URL+"/poll?id="+a.snapshot().ID, "wrong", Poll{}, nil) == nil {
		t.Fatal("bad session accepted")
	}
	if post(ctx, c, in.URL+"/api/job", a.secret, Input{Op: "shell", Command: "exit 0"}, nil) == nil {
		t.Fatal("remote control API exposed")
	}
	app := newApp(t.TempDir(), nil, true)
	if e := app.serve(); e != nil {
		t.Fatal(e)
	}
	defer app.close()
	if post(ctx, &http.Client{Timeout: time.Second}, app.url+"/api/job", "", Input{Key: app.key, Op: "shell"}, nil) == nil {
		t.Fatal("agent local control allowed")
	}
	if post(ctx, &http.Client{Timeout: time.Second}, app.url+"/api/status", "", Input{Key: "wrong"}, nil) == nil {
		t.Fatal("local missing auth")
	}
	h.revoke(a.snapshot().ID)
	eventually(t, 5*time.Second, func() bool { return a.snapshot().State == "closed" })
	if _, e := h.addJob(a.snapshot().ID, "shell", "exit 0", ""); e == nil {
		t.Fatal("revoked peer accepted task")
	}
}

func TestCancellationKeepsSessionAndKillsTree(t *testing.T) {
	h, in := testHub(t)
	a := testAgent(t, in, testEngine(t))
	path := filepath.Join(t.TempDir(), "child.pid")
	cmd := fmt.Sprintf("$p=Start-Process -FilePath $PSHOME\\pwsh.exe -ArgumentList '-NoProfile','-Command','Start-Sleep -Seconds 120' -WindowStyle Hidden -PassThru; [IO.File]::WriteAllText('%s',[string]$p.Id); Start-Sleep -Seconds 120", strings.ReplaceAll(path, "'", "''"))
	j := add(t, h, a, "shell", cmd, "")
	eventually(t, 10*time.Second, func() bool { _, e := os.Stat(path); return e == nil })
	pid, _ := os.ReadFile(path)
	if e := h.cancelJob(a.snapshot().ID, j.ID); e != nil {
		t.Fatal(e)
	}
	v := finished(t, h, a, j, 10*time.Second)
	if v.State != "cancelled" {
		t.Fatalf("cancel state %+v", v)
	}
	var out bytes.Buffer
	code, e := runShell(context.Background(), "if(Get-Process -Id "+string(pid)+" -ErrorAction SilentlyContinue){exit 7};'TREE_STOPPED'", &out)
	if code != 0 || e != nil {
		t.Fatal("child survived", string(pid), code, e)
	}
	next := finished(t, h, a, add(t, h, a, "shell", "'STILL_CONNECTED'", ""), 10*time.Second)
	if next.State != "completed" || !strings.Contains(next.Output, "STILL_CONNECTED") {
		t.Fatal("cancel killed session", next)
	}
}

func TestDualControllersSerialize(t *testing.T) {
	h1, i1 := testHub(t)
	h2, i2 := testHub(t)
	en := testEngine(t)
	a1 := testAgent(t, i1, en)
	a2 := testAgent(t, i2, en)
	path := strings.ReplaceAll(filepath.Join(t.TempDir(), "order.txt"), "'", "''")
	command := func(label string) string {
		return fmt.Sprintf("[IO.File]::AppendAllText('%s','%s-start;');Start-Sleep -Seconds 2;[IO.File]::AppendAllText('%s','%s-end;')", path, label, path, label)
	}
	j1 := add(t, h1, a1, "shell", command("A"), "")
	j2 := add(t, h2, a2, "shell", command("B"), "")
	v1 := finished(t, h1, a1, j1, 15*time.Second)
	v2 := finished(t, h2, a2, j2, 15*time.Second)
	b, _ := os.ReadFile(path)
	s := string(b)
	if v1.State != "completed" || v2.State != "completed" || (s != "A-start;A-end;B-start;B-end;" && s != "B-start;B-end;A-start;A-end;") {
		t.Fatal("overlapping commands", s, v1.State, v2.State)
	}
}

func TestCloseKillsTask(t *testing.T) {
	h, in := testHub(t)
	a := testAgent(t, in, testEngine(t))
	j := add(t, h, a, "shell", "'STARTED';Start-Sleep -Seconds 120; 'SHOULD_NOT_RUN'", "")
	eventually(t, 8*time.Second, func() bool { v, _ := h.job(a.snapshot().ID, j.ID); return strings.Contains(v.Output, "STARTED") })
	h.server.Close()
	select {
	case <-a.done:
	case <-time.After(8 * time.Second):
		t.Fatal("controller close did not cancel agent task")
	}
	if a.snapshot().Active != "" {
		t.Fatal("task still active")
	}
}

func TestEventReplayAndUnicodeBoundary(t *testing.T) {
	h, in := testHub(t)
	en := testEngine(t)
	a := newAgent(context.Background(), in, en)
	var w Welcome
	if e := post(a.ctx, a.client, in.URL+"/join", in.Key, Join{machine(), a.secret}, &w); e != nil {
		t.Fatal(e)
	}
	a.Status.ID = w.ID
	j := add(t, h, a, "shell", "unused", "")
	r := &reporter{a: a, id: j.ID}
	writer := &reportWriter{ctx: a.ctx, r: r}
	data := []byte("连续中文😀末尾")
	for _, b := range data {
		if _, e := writer.Write([]byte{b}); e != nil {
			t.Fatal(e)
		}
	}
	writer.flush()
	v, _ := h.job(w.ID, j.ID)
	if v.Output != string(data) {
		t.Fatal("UTF8 boundary corruption", v.Output)
	}
	before := v.Output
	if e := post(a.ctx, a.client, in.URL+"/event?id="+w.ID, a.secret, Event{ID: j.ID, Seq: 1, Output: "DUPLICATE"}, nil); e != nil {
		t.Fatal(e)
	}
	v, _ = h.job(w.ID, j.ID)
	if v.Output != before {
		t.Fatal("duplicate appended")
	}
	a.stop()
}

func TestFileAuthorizationAndCorruption(t *testing.T) {
	h, in := testHub(t)
	a := testAgent(t, in, testEngine(t))
	b := testAgent(t, in, testEngine(t))
	en := testEngine(t)
	_ = en
	// Hold execution so manual file requests cannot race the task consumer.
	a.engine.slot <- struct{}{}
	defer func() { <-a.engine.slot }()
	j := add(t, h, a, "get", "", filepath.Join(t.TempDir(), "source"))
	send := func(agent *Agent, hash string) int {
		req, _ := http.NewRequest("PUT", in.URL+"/blob?id="+agent.snapshot().ID+"&job="+j.ID, strings.NewReader("wrong bytes"))
		req.Header.Set("Authorization", "Bearer "+agent.secret)
		req.Header.Set("X-SHA256", hash)
		resp, e := a.client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	if code := send(b, strings.Repeat("0", 64)); code != 403 {
		t.Fatal("cross-agent file access", code)
	}
	if code := send(a, strings.Repeat("0", 64)); code == 200 {
		t.Fatal("corrupt upload accepted")
	}
	v, _ := h.job(a.snapshot().ID, j.ID)
	if _, e := os.Stat(v.DownloadPath); !os.IsNotExist(e) {
		t.Fatal("corrupt destination exists")
	}
	h.cancelJob(a.snapshot().ID, j.ID)
}

func TestIdentityPersists(t *testing.T) {
	root := t.TempDir()
	_, p, k, e := identity(root)
	if e != nil {
		t.Fatal(e)
	}
	_, p2, k2, e := identity(root)
	if e != nil || p != p2 || k != k2 {
		t.Fatal("controller identity changed")
	}
	b, _ := os.ReadFile(filepath.Join(root, "identity.json"))
	var id Identity
	if json.Unmarshal(b, &id) != nil || len(id.PrivateKey) == 0 {
		t.Fatal("identity missing")
	}
}

func TestLongRunningOver120Seconds(t *testing.T) {
	if os.Getenv("CONTROL-A_LONG_TEST") != "1" {
		t.Skip("set CONTROL-A_LONG_TEST=1")
	}
	h, in := testHub(t)
	a := testAgent(t, in, testEngine(t))
	start := time.Now()
	j := add(t, h, a, "shell", "'BEFORE';Start-Sleep -Seconds 125;'AFTER_125_SECONDS'", "")
	v := finished(t, h, a, j, 145*time.Second)
	if time.Since(start) < 125*time.Second || v.State != "completed" || !strings.Contains(v.Output, "AFTER_125_SECONDS") {
		t.Fatal("long job failed", v)
	}
	t.Log("125-second remote command completed")
}

func TestMachineReportToBothControllers(t *testing.T) {
	h1, i1 := testHub(t)
	h2, i2 := testHub(t)
	app := newApp(t.TempDir(), nil, true)
	defer app.close()
	app.connect(i1)
	app.connect(i2)
	eventually(t, 8*time.Second, func() bool {
		app.mu.Lock()
		defer app.mu.Unlock()
		return len(app.agents) == 2 && app.agents[0].snapshot().State == "connected" && app.agents[1].snapshot().State == "connected"
	})
	v, e := app.report("设计部·测试电脑")
	if e != nil || v["sent"] != 2 {
		t.Fatal("report failed", v, e)
	}
	for _, h := range []*Hub{h1, h2} {
		p := h.snapshot()[0]
		if p.Machine.Note != "设计部·测试电脑" || p.Joined.IsZero() || p.Reported.IsZero() || !strings.Contains(p.Information, "Computer") {
			t.Fatalf("incomplete report %+v", p)
		}
	}
}

func TestSingleInstance(t *testing.T) {
	root := t.TempDir()
	unlock, e := lockRoot(root)
	if e != nil {
		t.Fatal(e)
	}
	if other, e := lockRoot(root); e == nil {
		other()
		unlock()
		t.Fatal("second instance allowed")
	}
	unlock()
	next, e := lockRoot(root)
	if e != nil {
		t.Fatal("lock not released", e)
	}
	next()
}

func TestUISmoke(t *testing.T) {
	if os.Getenv("CONTROL-A_UI_TEST") != "1" {
		t.Skip("interactive UI smoke test")
	}
	h, in := testHub(t)
	app := newApp(t.TempDir(), h, true)
	defer app.close()
	if e := app.serve(); e != nil {
		t.Fatal(e)
	}
	a := testAgent(t, in, app.engine)
	app.mu.Lock()
	app.agents = append(app.agents, a)
	app.mu.Unlock()
	fmt.Println("UI_TEST_URL=" + app.url + "/#" + app.key)
	select {
	case <-app.ctx.Done():
	case <-time.After(5 * time.Minute):
	}
	t.Log("UI fixture closed")
}

// Keep concurrent cancellation paths exercised under -race when a C compiler is available.
func TestConcurrentStatus(t *testing.T) {
	h, in := testHub(t)
	a := testAgent(t, in, testEngine(t))
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 20; n++ {
				h.snapshot()
				a.snapshot()
			}
		}()
	}
	wg.Wait()
}

func TestIndependentServerMonitor(t *testing.T) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	v := Monitor{ID: "test", Name: "test service", Host: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port}
	got := probeMonitor(context.Background(), v)
	if got.State != "服务可达" || got.LastSeen.IsZero() {
		t.Fatal("probe", got)
	}
	l.Close()
	got = probeMonitor(context.Background(), got)
	if got.State != "服务不可达" || got.LastSeen.IsZero() {
		t.Fatal("offline probe", got)
	}
	for _, host := range []string{"8.8.8.8", "http://192.168.1.2", "x/../../x", "", "name user"} {
		if validMonitor(host, 445) {
			t.Fatal("invalid monitor accepted", host)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newMonitors(ctx, t.TempDir())
	if e = m.add("独立服务器", "10.77.0.11", 445); e != nil {
		t.Fatal(e)
	}
	id := m.snapshot()[0].ID
	if e = m.remove(id); e != nil || len(m.snapshot()) != 0 {
		t.Fatal("remove", e)
	}
}

func TestBrowserJavaScriptSyntax(t *testing.T) {
	start := strings.Index(page, "<script>") + len("<script>")
	end := strings.Index(page, "</script>")
	if start < 8 || end < start {
		t.Fatal("missing script")
	}
	cmd := exec.Command("node", "--check")
	cmd.Stdin = strings.NewReader(page[start:end])
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatal(e, string(out))
	}
}

func TestReconnectWithoutReplayingJobs(t *testing.T) {
	h, in := testHub(t)
	app := newApp(t.TempDir(), nil, true)
	defer app.close()
	app.profiles([]Profile{{Name: "CONTROL-A", Invites: []Invite{in}}})
	state := func() AgentStatus { app.mu.Lock(); defer app.mu.Unlock(); return app.agents[0].snapshot() }
	eventually(t, 8*time.Second, func() bool { return state().State == "connected" })
	first := state().ID
	h.server.Close()
	eventually(t, 6*time.Second, func() bool { return state().State != "connected" })
	h2 := newHub(t.TempDir(), h.cert, h.pin, h.key, true)
	if e := h2.start(strings.TrimPrefix(in.URL, "https://")); e != nil {
		t.Fatal(e)
	}
	defer h2.close()
	eventually(t, 10*time.Second, func() bool { return state().State == "connected" && state().ID != first })
	h2.revoke(state().ID)
	eventually(t, 6*time.Second, func() bool { return state().State == "closed" })
	time.Sleep(2500 * time.Millisecond)
	if len(h2.snapshot()) != 1 || state().State != "closed" {
		t.Fatal("explicit revoke was bypassed by reconnect")
	}
}
