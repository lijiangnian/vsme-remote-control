package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type AgentStatus struct {
	Name       string    `json:"name,omitempty"`
	Joined     time.Time `json:"joined"`
	Controller string    `json:"controller"`
	State      string    `json:"state"`
	Error      string    `json:"error"`
	ID         string    `json:"id"`
	Active     string    `json:"active"`
	Last       time.Time `json:"last"`
}

// Shared by connections to both controllers: at most one task executes on a machine.
type Engine struct {
	addresses *addressBook
	slot      chan struct{}
	root      string
	audit     *Audit
}

func newEngine(root string) *Engine {
	os.MkdirAll(root, 0700)
	return &Engine{slot: make(chan struct{}, 1), root: root, audit: auditOpen(root), addresses: newAddressBook(root)}
}

type Agent struct {
	profile      *Profile
	workers      sync.WaitGroup
	candidates   []Invite
	mu           sync.Mutex
	Status       AgentStatus
	in           Invite
	engine       *Engine
	client       *http.Client
	ctx          context.Context
	cancel       context.CancelFunc
	secret       string
	activeCancel context.CancelFunc
	done         chan struct{}
	revoked      bool
}

func newAgent(parent context.Context, in Invite, engine *Engine) *Agent {
	ctx, cancel := context.WithCancel(parent)
	return &Agent{in: in, engine: engine, ctx: ctx, cancel: cancel, secret: token(), client: pinnedClient(in.Pin), done: make(chan struct{}), Status: AgentStatus{Controller: in.URL, State: "connecting"}}
}
func (a *Agent) snapshot() AgentStatus { a.mu.Lock(); defer a.mu.Unlock(); return a.Status }
func (a *Agent) update(state string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Status.State = state
	a.Status.Error = ""
	if err != nil {
		a.Status.Error = err.Error()
	}
	if err == nil {
		a.Status.Last = time.Now()
	}
}
func (a *Agent) stop() {
	a.cancel()
	a.mu.Lock()
	if a.activeCancel != nil {
		a.activeCancel()
	}
	a.mu.Unlock()
}
func (a *Agent) run() {
	defer close(a.done)
	defer func() {
		st := a.snapshot()
		a.engine.audit.log("connection-ended", map[string]string{"controller": st.Controller, "id": st.ID, "error": st.Error})
	}()
	defer a.workers.Wait()
	defer func() { a.mu.Lock(); a.Status.State = "closed"; a.mu.Unlock() }()
	defer func() { a.client.CloseIdleConnections() }()
joinLoop:
	for {
		candidates := a.candidates
		if a.profile != nil {
			candidates = a.engine.addresses.candidates(*a.profile)
		}
		if len(candidates) == 0 {
			candidates = []Invite{a.in}
		}
		attemptErrors := []string{}
		for _, candidate := range candidates {
			if a.ctx.Err() != nil {
				return
			}
			a.client.CloseIdleConnections()
			a.in = candidate
			a.client = pinnedClient(a.in.Pin)
			a.mu.Lock()
			a.Status.Controller = a.in.URL
			a.mu.Unlock()
			var w Welcome
			ctx, cancel := context.WithTimeout(a.ctx, 2500*time.Millisecond)
			e := post(ctx, a.client, a.in.URL+"/join", a.in.Key, Join{a.engine.machine(), a.secret}, &w)
			cancel()
			if e == nil {
				if a.profile != nil {
					a.engine.addresses.remember(*a.profile, a.in.URL)
				}
				a.mu.Lock()
				a.Status.ID = w.ID
				a.Status.Joined = time.Now()
				a.mu.Unlock()
				break joinLoop
			}
			attemptErrors = append(attemptErrors, a.in.URL+": "+e.Error())
			a.update("connecting", e)
		}
		if a.profile != nil {
			if a.engine.addresses.refreshDirectory(a.ctx, *a.profile) {
				continue
			}
			a.update("discovering", fmt.Errorf("已配置地址未接通，正在核验证书并查找最新地址；%s", strings.Join(attemptErrors, "；")))
			if a.engine.addresses.discover(a.ctx, *a.profile) != "" {
				continue
			}
		}
		a.update("connecting", fmt.Errorf("%s；可在本机身份页填写主控当前 IP 重试", strings.Join(attemptErrors, "；")))
		select {
		case <-a.ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
	id := a.snapshot().ID
	defer func() {
		ctx, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		post(ctx, a.client, a.in.URL+"/leave?id="+id, a.secret, struct{}{}, nil)
	}()
	pollClient := *a.client
	pollClient.Timeout = 3 * time.Second
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		if a.ctx.Err() != nil {
			return
		}
		st := a.snapshot()
		var out Delivery
		e := post(a.ctx, &pollClient, a.in.URL+"/poll?id="+id, a.secret, Poll{st.Active}, &out)
		if e != nil {
			a.update("disconnected", e)
			a.stop()
			return
		} else {
			a.update("connected", nil)
			if out.Cancel != "" {
				a.mu.Lock()
				if a.Status.Active == out.Cancel && a.activeCancel != nil {
					a.activeCancel()
				}
				a.mu.Unlock()
			}
			if out.Job != nil {
				a.mu.Lock()
				if a.Status.Active == "" {
					ctx, cancel := context.WithCancel(a.ctx)
					a.activeCancel = cancel
					a.Status.Active = out.Job.ID
					a.workers.Add(1)
					go func() { defer a.workers.Done(); a.execute(ctx, out.Job) }()
				}
				a.mu.Unlock()
			}
		}
		select {
		case <-a.ctx.Done():
			return
		case <-t.C:
		}
	}
}

type reporter struct {
	mu       sync.Mutex
	a        *Agent
	id       string
	seq      int64
	progress int64
}

func (r *reporter) send(ctx context.Context, ev Event) error {
	// A task cancellation must not cancel the connection or leave an event sequence gap.
	ctx = r.a.ctx
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	ev.ID = r.id
	ev.Seq = r.seq
	if ev.Progress > 0 {
		r.progress = ev.Progress
	}
	ev.Progress = r.progress
	deadline := time.Now().Add(lease)
	for {
		e := post(ctx, r.a.client, r.a.in.URL+"/event?id="+r.a.snapshot().ID, r.a.secret, ev, nil)
		if e == nil {
			return nil
		}
		if ctx.Err() != nil || strings.Contains(e.Error(), "HTTP 403") || strings.Contains(e.Error(), "HTTP 410") || time.Now().After(deadline) {
			r.a.update("disconnected", e)
			r.a.stop()
			return e
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

type reportWriter struct {
	mu      sync.Mutex
	pending []byte
	ctx     context.Context
	r       *reporter
}

func (w *reportWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(b)
	b = append(w.pending, b...)
	w.pending = nil
	for len(b) > 0 {
		end := len(b)
		if end > 16384 {
			end = 16384
		}
		start := end - 1
		for start > 0 && !utf8.RuneStart(b[start]) {
			start--
		}
		if !utf8.FullRune(b[start:end]) {
			end = start
		}
		if end == 0 {
			w.pending = append([]byte{}, b...)
			break
		}
		if e := w.r.send(w.ctx, Event{Output: string(b[:end])}); e != nil {
			return 0, e
		}
		b = b[end:]
	}
	return n, nil
}
func (w *reportWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.pending) > 0 {
		w.r.send(w.ctx, Event{Output: strings.ToValidUTF8(string(w.pending), "�")})
		w.pending = nil
	}
}
func (a *Agent) execute(ctx context.Context, j *Job) {
	defer func() { a.mu.Lock(); a.Status.Active = ""; a.activeCancel = nil; a.mu.Unlock() }()
	r := &reporter{a: a, id: j.ID}
	if r.send(ctx, Event{State: "running", Output: "已接收任务；等待本机执行队列。\n"}) != nil {
		return
	}
	select {
	case a.engine.slot <- struct{}{}:
		defer func() { <-a.engine.slot }()
	case <-ctx.Done():
		r.send(a.ctx, Event{State: "cancelled", Exit: -1})
		return
	}
	a.engine.audit.log("start", map[string]any{"controller": a.in.URL, "job": j})
	var err error
	exit := 0
	outputWriter := &reportWriter{ctx: ctx, r: r}
	switch j.Op {
	case "shell":
		exit, err = runShell(ctx, j.Command, outputWriter)
	case "info":
		exit, err = runShell(ctx, infoScript(), outputWriter)
	case "put":
		err = a.receive(ctx, j, r)
	case "get":
		err = a.upload(ctx, j, r)
	default:
		err = errors.New("unsupported operation")
	}
	outputWriter.flush()
	state := "completed"
	if err != nil || exit != 0 {
		state = "failed"
	}
	if ctx.Err() != nil {
		state = "cancelled"
	}
	output := ""
	if err != nil {
		output = err.Error() + "\n"
		if exit == 0 {
			exit = -1
		}
	}
	a.engine.audit.log("result", map[string]any{"job": j.ID, "state": state, "exit": exit})
	r.send(a.ctx, Event{State: state, Exit: exit, Output: output})
}
func (a *Agent) receive(ctx context.Context, j *Job, r *reporter) error {
	if j.Size < 0 || j.Size > maxFile || len(j.Hash) != 64 {
		return errors.New("invalid file metadata")
	}
	name := filepath.Base(j.Name)
	if name == "." || name == "" || strings.ContainsAny(name, "/\\:") {
		return errors.New("invalid file name")
	}
	dir := filepath.Join(a.engine.root, "Incoming")
	os.MkdirAll(dir, 0700)
	part := filepath.Join(dir, j.Hash+".part")
	dest := filepath.Join(dir, j.ID+"-"+name)
	var offset int64
	if f, e := os.Stat(part); e == nil {
		offset = f.Size()
	}
	if offset > j.Size {
		return errors.New("invalid partial length")
	}
	for offset < j.Size {
		req, e := http.NewRequestWithContext(ctx, "GET", a.in.URL+"/blob?id="+a.snapshot().ID+"&job="+j.ID, nil)
		if e != nil {
			return e
		}
		end := offset + (256 << 10) - 1
		if end >= j.Size {
			end = j.Size - 1
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, end))
		req.Header.Set("Authorization", "Bearer "+a.secret)
		resp, e := a.client.Do(req)
		if e != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
				continue
			}
		}
		if resp.StatusCode != 206 && !(offset == 0 && resp.StatusCode == 200) {
			resp.Body.Close()
			return fmt.Errorf("file HTTP %d", resp.StatusCode)
		}
		f, e := os.OpenFile(part, os.O_CREATE|os.O_WRONLY, 0600)
		if e != nil {
			resp.Body.Close()
			return e
		}
		f.Seek(offset, 0)
		n, e := io.Copy(f, io.LimitReader(resp.Body, end-offset+1))
		f.Close()
		resp.Body.Close()
		offset += n
		if e != nil {
			continue
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		if e = r.send(ctx, Event{Progress: offset}); e != nil {
			return e
		}
	}
	if j.Size == 0 {
		os.WriteFile(part, nil, 0600)
	}
	sum, e := hashFile(part)
	if e != nil {
		return e
	}
	if !same(sum, j.Hash) {
		os.Remove(part)
		return errors.New("SHA-256 mismatch")
	}
	if _, e = os.Stat(dest); e == nil {
		return errors.New("destination exists")
	}
	if e = os.Rename(part, dest); e != nil {
		return e
	}
	return r.send(ctx, Event{Path: dest, Hash: sum, Progress: j.Size, Output: "文件已校验：" + dest + "\n"})
}

type progressReader struct {
	f     *os.File
	r     *reporter
	ctx   context.Context
	bytes int64
	last  time.Time
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, e := p.f.Read(b)
	p.bytes += int64(n)
	if time.Since(p.last) > time.Second {
		p.last = time.Now()
		if err := p.r.send(p.ctx, Event{Progress: p.bytes}); err != nil {
			return n, err
		}
	}
	return n, e
}
func (a *Agent) upload(ctx context.Context, j *Job, r *reporter) error {
	if !filepath.IsAbs(j.Path) {
		return errors.New("absolute file path required")
	}
	f, e := os.Open(j.Path)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() || st.Size() > maxFile {
		return errors.New("普通文件最大 2 GB")
	}
	sum, e := hashFile(j.Path)
	if e != nil {
		return e
	}
	if e = r.send(ctx, Event{Hash: sum, Size: st.Size()}); e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, "PUT", a.in.URL+"/blob?id="+a.snapshot().ID+"&job="+j.ID, &progressReader{f: f, r: r, ctx: ctx})
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+a.secret)
	req.Header.Set("X-SHA256", sum)
	req.ContentLength = st.Size()
	client := *a.client
	client.Timeout = 30 * time.Minute
	resp, e := client.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("upload HTTP %d: %s", resp.StatusCode, b)
	}
	return r.send(ctx, Event{Progress: st.Size(), Output: "回传文件已通过 SHA-256 校验。\n"})
}
