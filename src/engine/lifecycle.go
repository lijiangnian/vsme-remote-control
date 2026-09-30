package main

import (
	"fmt"
	"io"
	"strings"
	"time"
)

func (a *App) shutdown(reason string) {
	a.stopOnce.Do(func() {
		a.engine.audit.log("application-stop", map[string]string{"reason": reason})
		fmt.Println("维修通道停止：", reason)
		a.cancel()
	})
}

func (a *App) watchOwnerInput(r io.Reader) {
	_, _ = io.Copy(io.Discard, r)
	if a.ctx.Err() == nil {
		a.shutdown("启动窗口已关闭或标准输入已结束")
	}
}

func (a *App) browserLeaseExpired(now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.headless && !a.terminalOwned && ((a.seenUI && now.Sub(a.lastUI) > 15*time.Second) || (!a.seenUI && now.Sub(a.lastUI) > 2*time.Minute))
}

func (a *App) pageContent() string {
	if a.terminalOwned {
		return strings.Replace(page, "const terminalLifecycle=false;", "const terminalLifecycle=true;", 1)
	}
	return page
}
