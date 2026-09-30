package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Details struct {
	Machine     Machine `json:"machine"`
	Information string  `json:"information"`
}

func (e *Engine) machine() Machine {
	m := machine()
	var note string
	b, err := os.ReadFile(filepath.Join(e.root, "device-name.json"))
	if err == nil {
		json.Unmarshal(b, &note)
		m.Note = note
	}
	return m
}
func (h *Hub) details(w http.ResponseWriter, r *http.Request) {
	var d Details
	if r.Method != "POST" || decode(r, &d) != nil || len(d.Information) > 65536 || len(d.Machine.Note) > 240 {
		http.Error(w, "bad details", 400)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	p := h.auth(r)
	if p == nil {
		h.authFailureLocked(w, r)
		return
	}
	if !strings.EqualFold(p.Machine.Name, d.Machine.Name) {
		http.Error(w, "identity changed", 400)
		return
	}
	p.Machine = d.Machine
	p.Information = d.Information
	p.Reported = time.Now()
	p.Last = time.Now()
	h.audit.log("information-reported", map[string]string{"id": p.ID, "name": p.Machine.Name, "note": p.Machine.Note})
	reply(w, map[string]bool{"ok": true})
}
func (a *App) report(note string) (map[string]any, error) {
	note = strings.TrimSpace(note)
	if len(note) > 240 {
		return nil, fmt.Errorf("备注过长，请限制为 80 个汉字以内")
	}
	if e := writeJSON(filepath.Join(a.engine.root, "device-name.json"), note); e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(a.ctx, 25*time.Second)
	defer cancel()
	select {
	case a.engine.slot <- struct{}{}:
		defer func() { <-a.engine.slot }()
	default:
		return nil, fmt.Errorf("本机正在执行任务，请等任务结束再发送信息")
	}
	var out bytes.Buffer
	code, e := runShell(ctx, infoScript(), &out)
	if e != nil || code != 0 {
		return nil, fmt.Errorf("读取本机信息失败：%v", e)
	}
	if out.Len() > 65536 {
		return nil, fmt.Errorf("本机信息超过限制")
	}
	d := Details{a.engine.machine(), out.String()}
	a.mu.Lock()
	ags := append([]*Agent{}, a.agents...)
	a.mu.Unlock()
	sent := 0
	failures := []string{}
	for _, ag := range ags {
		st := ag.snapshot()
		if st.State != "connected" {
			continue
		}
		if e := post(ctx, ag.client, ag.in.URL+"/details?id="+st.ID, ag.secret, d, nil); e != nil {
			failures = append(failures, st.Controller+": "+e.Error())
		} else {
			sent++
		}
	}
	return map[string]any{"sent": sent, "errors": failures, "information": d.Information}, nil
}
