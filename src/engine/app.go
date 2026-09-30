package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type App struct {
	monitors      *MonitorSet
	ctx           context.Context
	cancel        context.CancelFunc
	hub           *Hub
	engine        *Engine
	mu            sync.Mutex
	agents        []*Agent
	key           string
	lastUI        time.Time
	seenUI        bool
	api           *http.Server
	url           string
	root          string
	headless      bool
	terminalOwned bool
	stopOnce      sync.Once
}
type Local struct {
	URL string `json:"url"`
	Key string `json:"key"`
	PID int    `json:"pid"`
}
type Input struct {
	Controller string `json:"controller"`
	Address    string `json:"address"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Note       string `json:"note"`
	Key        string `json:"key"`
	Agent      string `json:"agent"`
	Job        string `json:"job"`
	Op         string `json:"op"`
	Command    string `json:"command"`
	Path       string `json:"path"`
	Invite     string `json:"invite"`
}

func newApp(root string, h *Hub, headless bool) *App {
	ctx, c := context.WithCancel(context.Background())
	a := &App{ctx: ctx, cancel: c, hub: h, engine: newEngine(filepath.Join(root, "agent")), root: root, key: token(), lastUI: time.Now(), headless: headless}
	if h != nil {
		a.monitors = newMonitors(ctx, root)
		go a.publishAddresses()
	}
	return a
}
func (a *App) close() {
	a.cancel()
	a.mu.Lock()
	agents := append([]*Agent{}, a.agents...)
	a.mu.Unlock()
	for _, ag := range agents {
		ag.stop()
	}
	for _, ag := range agents {
		select {
		case <-ag.done:
		case <-time.After(6 * time.Second):
		}
	}
	if a.hub != nil {
		a.hub.close()
	}
	if a.api != nil {
		a.api.Close()
	}
	a.engine.audit.close()
}
func (a *App) connect(in Invite) {
	ag := newAgent(a.ctx, in, a.engine)
	a.mu.Lock()
	a.agents = append(a.agents, ag)
	a.mu.Unlock()
	go ag.run()
}
func (a *App) profiles(v []Profile) {
	for _, p := range v {
		if a.hub != nil && strings.EqualFold(p.Name, machine().Name) {
			continue
		}
		if len(p.Invites) == 0 {
			continue
		}
		ag := newAgent(a.ctx, p.Invites[0], a.engine)
		ag.candidates = p.Invites
		ag.profile = &p
		ag.Status.Name = p.Name
		a.mu.Lock()
		index := len(a.agents)
		a.agents = append(a.agents, ag)
		a.mu.Unlock()
		go a.maintainProfile(index, p, ag)
	}
}
func (a *App) maintainProfile(index int, p Profile, ag *Agent) {
	for {
		ag.run()
		if a.ctx.Err() != nil || strings.Contains(ag.snapshot().Error, "HTTP 403") {
			return
		}
		select {
		case <-a.ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
		ag = newAgent(a.ctx, p.Invites[0], a.engine)
		ag.candidates = p.Invites
		ag.profile = &p
		ag.Status.Name = p.Name
		a.mu.Lock()
		if a.ctx.Err() != nil {
			a.mu.Unlock()
			ag.stop()
			return
		}
		a.agents[index] = ag
		a.mu.Unlock()
	}
}
func (a *App) serve() error {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return e
	}
	a.url = "http://" + l.Addr().String()
	m := http.NewServeMux()
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'")
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, a.pageContent())
	})
	m.HandleFunc("/api/", a.handle)
	a.api = &http.Server{Handler: m, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second}
	go a.api.Serve(l)
	if e = writeJSON(filepath.Join(a.root, "control.json"), Local{a.url, a.key, os.Getpid()}); e != nil {
		return e
	}
	if !a.headless {
		go func() {
			t := time.NewTicker(time.Second)
			defer t.Stop()
			for {
				select {
				case <-a.ctx.Done():
					return
				case <-t.C:
					if a.browserLeaseExpired(time.Now()) {
						a.shutdown("旧网页模式心跳超时")
						return
					}
				}
			}
		}()
	}
	return nil
}
func (a *App) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || r.Host != strings.TrimPrefix(a.url, "http://") {
		http.Error(w, "local POST only", 403)
		return
	}
	var in Input
	if decode(r, &in) != nil || !same(in.Key, a.key) {
		http.Error(w, "unauthorized", 403)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	switch r.URL.Path {
	case "/api/import-controller-address":
		v, e := parseAddressBundle(in.Invite)
		if e == nil {
			e = a.setControllerAddresses(v)
		}
		if e != nil {
			fail(w, e)
			return
		}
		names := []string{}
		addresses := []string{}
		for _, share := range v {
			names = append(names, share.Name)
			addresses = append(addresses, share.IPs[0])
		}
		reply(w, map[string]string{"controller": strings.Join(names, " + "), "address": strings.Join(addresses, " + ")})
	case "/api/controller-address":
		if e := a.setControllerAddress(in.Controller, in.Address); e != nil {
			fail(w, e)
			return
		}
		reply(w, map[string]bool{"ok": true})
	case "/api/report":
		v, e := a.report(in.Note)
		if e != nil {
			fail(w, e)
			return
		}
		reply(w, v)
	case "/api/lease":
		a.mu.Lock()
		a.lastUI = time.Now()
		a.seenUI = true
		a.mu.Unlock()
		reply(w, map[string]bool{"ok": true})
	case "/api/stop":
		reply(w, map[string]bool{"ok": true})
		a.shutdown("用户点击停止授权")
	case "/api/connect":
		v, e := parseInvite(in.Invite)
		if e != nil {
			fail(w, e)
			return
		}
		a.connect(v)
		reply(w, map[string]bool{"ok": true})
	case "/api/status":
		agents := []AgentStatus{}
		a.mu.Lock()
		for _, ag := range a.agents {
			agents = append(agents, ag.snapshot())
		}
		a.mu.Unlock()
		out := map[string]any{"version": version, "build": "2.1.1-terminal-lifecycle", "terminal_owned": a.terminalOwned, "machine": a.engine.machine(), "role": defaultRole, "connections": agents}
		if a.hub != nil {
			out["servers"] = a.monitors.snapshot()
			out["peers"] = a.hub.snapshot()
			out["role"] = "controller"
			out["urls"] = a.hub.urls
			codes := []string{}
			for _, u := range a.hub.urls {
				codes = append(codes, (Invite{u, a.hub.pin, a.hub.key}).String())
			}
			out["codes"] = codes
		}
		reply(w, out)
	default:
		if a.hub == nil {
			http.Error(w, "controlled device cannot issue commands", 403)
			return
		}
		switch r.URL.Path {
		case "/api/share-controller-address":
			value, e := a.shareControllerAddresses()
			if e != nil {
				fail(w, e)
				return
			}
			reply(w, map[string]string{"text": value})
		case "/api/ssh-info":
			ctx, cancel := context.WithTimeout(a.ctx, 25*time.Second)
			defer cancel()
			cmd, e := sshCommand(ctx, in.Host, infoScript())
			if e != nil {
				fail(w, e)
				return
			}
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			e = cmd.Run()
			if e != nil {
				fail(w, fmt.Errorf("SSH 读取失败：%v\n%s", e, output.String()))
				return
			}
			a.hub.audit.log("ssh-info", in.Host)
			reply(w, map[string]any{"information": output.String(), "time": time.Now()})
		case "/api/server-add":
			e := a.monitors.add(in.Note, in.Host, in.Port)
			if e != nil {
				fail(w, e)
				return
			}
			reply(w, map[string]bool{"ok": true})
		case "/api/server-remove":
			e := a.monitors.remove(in.Agent)
			if e != nil {
				fail(w, e)
				return
			}
			reply(w, map[string]bool{"ok": true})
		case "/api/approve":
			a.hub.mu.Lock()
			if p := a.hub.Peers[in.Agent]; p != nil {
				p.Approved = true
			}
			a.hub.mu.Unlock()
			reply(w, map[string]bool{"ok": true})
		case "/api/revoke":
			a.hub.revoke(in.Agent)
			reply(w, map[string]bool{"ok": true})
		case "/api/job":
			j, e := a.hub.addJob(in.Agent, in.Op, in.Command, in.Path)
			if e != nil {
				fail(w, e)
				return
			}
			reply(w, j)
		case "/api/result":
			j, e := a.hub.job(in.Agent, in.Job)
			if e != nil {
				fail(w, e)
				return
			}
			reply(w, j)
		case "/api/cancel":
			e := a.hub.cancelJob(in.Agent, in.Job)
			if e != nil {
				fail(w, e)
				return
			}
			reply(w, map[string]bool{"ok": true})
		case "/api/prompt":
			reply(w, map[string]string{"text": a.hub.prompt(in.Agent)})
		default:
			http.NotFound(w, r)
		}
	}
}
func localCall(endpoint string, in Input, out any) error {
	b, e := os.ReadFile(filepath.Join(dataRoot(), "control.json"))
	if e != nil {
		return errors.New("请先以管理员身份打开本机控制端")
	}
	var l Local
	if e = json.Unmarshal(b, &l); e != nil {
		return e
	}
	in.Key = l.Key
	return post(context.Background(), &http.Client{Timeout: 40 * time.Second}, l.URL+"/api/"+endpoint, "", in, out)
}
func runCLI(args []string) error {
	if len(args) == 0 {
		return nil
	}
	if strings.HasPrefix(args[0], "ssh-") {
		return runSSHCLI(args)
	}
	if args[0] == "set-controller" {
		if len(args) != 3 {
			return errors.New("用法：set-controller CONTROL-A或CONTROL-B 当前局域网IPv4；空地址恢复自动")
		}
		var out any
		if e := localCall("controller-address", Input{Controller: args[1], Address: args[2]}, &out); e != nil {
			return e
		}
		fmt.Println("地址已保存；正在使用原有证书核验并重连。")
		return nil
	}
	if args[0] == "share-address" {
		var out map[string]string
		if e := localCall("share-controller-address", Input{}, &out); e != nil {
			return e
		}
		fmt.Println(out["text"])
		return nil
	}
	if args[0] == "list" {
		var out map[string]any
		if e := localCall("status", Input{}, &out); e != nil {
			return e
		}
		delete(out, "codes")
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	if len(args) < 2 {
		return errors.New("用法: list | info ID | run ID 命令 | start ID 命令 | jobs ID | status ID JOB | cancel ID JOB | send ID 文件 | get ID 文件 | prompt ID")
	}
	op := args[0]
	in := Input{Agent: args[1]}
	if op == "prompt" {
		var v map[string]string
		if e := localCall("prompt", in, &v); e != nil {
			return e
		}
		fmt.Println(v["text"])
		return nil
	}
	if op == "jobs" {
		var v struct {
			Peers []Peer `json:"peers"`
		}
		if e := localCall("status", in, &v); e != nil {
			return e
		}
		for _, p := range v.Peers {
			if p.ID == in.Agent {
				b, _ := json.MarshalIndent(p.Jobs, "", "  ")
				fmt.Println(string(b))
				return nil
			}
		}
		return errors.New("unknown peer")
	}
	if op == "status" || op == "cancel" {
		if len(args) < 3 {
			return errors.New("需要任务 ID")
		}
		in.Job = args[2]
		var out any
		ep := "result"
		if op == "cancel" {
			ep = "cancel"
		}
		if e := localCall(ep, in, &out); e != nil {
			return e
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	switch op {
	case "info":
		in.Op = "info"
	case "run", "start", "run-file", "start-file":
		if len(args) < 3 {
			return errors.New("需要命令")
		}
		in.Op = "shell"
		in.Command = strings.Join(args[2:], " ")
		if op == "run-file" || op == "start-file" {
			f, e := os.Open(args[2])
			if e != nil {
				return e
			}
			b, e := io.ReadAll(io.LimitReader(f, 100001))
			f.Close()
			if e != nil {
				return e
			}
			if len(b) > 100000 {
				return errors.New("脚本超过 100 KB")
			}
			in.Command = strings.TrimPrefix(string(b), "\ufeff")
		}
	case "send", "get":
		if len(args) < 3 {
			return errors.New("需要文件路径")
		}
		in.Path = args[2]
		if op == "send" {
			in.Op = "put"
			in.Path, _ = filepath.Abs(in.Path)
		} else {
			in.Op = "get"
		}
	default:
		return errors.New("unknown command")
	}
	var j Job
	if e := localCall("job", in, &j); e != nil {
		return e
	}
	fmt.Println("JOB_ID=" + j.ID)
	if op == "start" || op == "start-file" {
		return nil
	}
	offset := 0
	for {
		var out Job
		if e := localCall("result", Input{Agent: in.Agent, Job: j.ID}, &out); e != nil {
			return e
		}
		if len(out.Output) > offset {
			fmt.Print(out.Output[offset:])
			offset = len(out.Output)
		}
		if out.State != "queued" && out.State != "running" {
			fmt.Println("STATE=" + out.State)
			if out.State != "completed" {
				return fmt.Errorf("任务退出码 %d", out.Exit)
			}
			return nil
		}
		time.Sleep(700 * time.Millisecond)
	}
}
