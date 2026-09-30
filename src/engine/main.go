package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"
)

func main() {
	if e := mainRun(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func mainRun() error {
	if len(os.Args) > 1 && len(os.Args[1]) > 0 && os.Args[1][0] != '-' {
		if defaultRole != "controller" && os.Args[1] != "set-controller" {
			return fmt.Errorf("此程序是被控端，不提供控制命令")
		}
		return runCLI(os.Args[1:])
	}
	f := flag.NewFlagSet("CONTROL-A Repair v2", flag.ContinueOnError)
	export := f.Bool("export-profile", false, "输出本机公共连接配置")
	headless := f.Bool("headless", false, "测试/终端运行")
	native := f.Bool("native-ui", false, "原生窗口托管；标准输入关闭即退出")
	duration := f.Duration("duration", 0, "自动退出时间")
	config := f.String("config", "", "双控制端配置文件")
	invite := f.String("invite", "", "本次连接码")
	listen := f.String("listen", ":45842", "控制端监听地址")
	root := f.String("data", dataRoot(), "本机数据目录")
	if e := f.Parse(os.Args[1:]); e != nil {
		return e
	}
	if *native && !*headless {
		return fmt.Errorf("原生窗口托管必须使用终端模式")
	}
	if *headless && !*native && (*duration <= 0 || *duration > time.Hour) {
		return fmt.Errorf("终端模式必须指定 --duration，范围为 1 秒到 1 小时")
	}
	if !isAdmin() && !*export {
		msg := "请右键程序 → 以管理员身份运行。"
		if runtime.GOOS == "darwin" {
			msg = "请双击包内“双击启动苹果被控端.command”，输入本机管理员密码启动。"
		}
		alert(msg)
		return fmt.Errorf("%s", msg)
	}
	if e := privateDir(*root); e != nil {
		return e
	}
	if !*export {
		unlock, e := lockRoot(*root)
		if e != nil {
			alert(e.Error())
			return e
		}
		defer unlock()
	}
	var hub *Hub
	if defaultRole == "controller" {
		c, p, k, e := identity(*root)
		if e != nil {
			return e
		}
		if *export {
			n, _ := os.Hostname()
			v := Profile{Name: n}
			for _, ip := range localIPs() {
				v.Invites = append(v.Invites, Invite{"https://" + ip + ":45842", p, k})
			}
			v.Invites = append(v.Invites, Invite{"https://" + n + ":45842", p, k})
			return json.NewEncoder(os.Stdout).Encode(v)
		}
		// A deployment must explicitly register this host AND its existing identity.
		profiles, err := loadFleet(*config)
		if err != nil {
			return fmt.Errorf("请先按 README 配对两台主控：%w", err)
		}
		own, _ := os.Hostname()
		authorized := false
		for _, profile := range profiles {
			if strings.EqualFold(profile.Name, own) && profile.Invites[0].Pin == p && profile.Invites[0].Key == k {
				authorized = true
			}
		}
		if !authorized {
			return fmt.Errorf("本机未登记为主控，或配置与本机身份不一致；不能自动更换证书")
		}
		addr, e := net.ResolveTCPAddr("tcp4", *listen)
		if e != nil || addr.Port < 1 {
			return fmt.Errorf("监听地址无效，请使用指定的非零端口")
		}
		exe, _ := os.Executable()
		closeFW, e := firewall(exe, addr.Port)
		if e != nil {
			return e
		}
		defer closeFW()
		hub = newHub(*root, c, p, k, true)
		if e = hub.start(*listen); e != nil {
			hub.close()
			return e
		}
	}
	app := newApp(*root, hub, *headless)
	defer app.close()
	if runtime.GOOS == "darwin" && !*headless {
		if !terminalAttached() {
			return fmt.Errorf("苹果临时被控端必须从可见终端打开；请双击包内启动文件，不允许脱离窗口常驻")
		}
		app.terminalOwned = true
	}
	if e := app.serve(); e != nil {
		return e
	}
	if *native || app.terminalOwned {
		go app.watchOwnerInput(os.Stdin)
	}
	if v, e := loadFleet(*config); e == nil {
		app.profiles(v)
	} else if *invite == "" {
		return fmt.Errorf("控制端配置无法读取：%v", e)
	}
	if *invite != "" {
		v, e := parseInvite(*invite)
		if e != nil {
			return e
		}
		app.connect(v)
	}
	if *duration > 0 {
		time.AfterFunc(*duration, func() { app.shutdown("限时测试结束") })
	}
	if *native {
		b, _ := json.Marshal(Local{app.url, app.key, os.Getpid()})
		fmt.Println("NATIVE_READY=" + string(b))
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, shutdownSignals()...)
	defer signal.Stop(sig)
	go func() {
		select {
		case reason := <-sig:
			app.shutdown("启动终端关闭或收到系统退出信号：" + reason.String())
		case <-app.ctx.Done():
		}
	}()
	url := app.url + "/#" + app.key
	fmt.Println("CONTROL-A 远程维修", version, "·", defaultRole, "·", machine().Name)
	if defaultRole == "controller" {
		fmt.Println("关闭此界面停止临时副机管理；既有 SSH 常驻互控与服务器权限不受影响。界面：", url)
	} else {
		fmt.Println("关闭此程序会撤销本次副机维修权限。界面：", url)
	}
	if app.terminalOwned {
		fmt.Println("苹果连接稳定修复版 2.1.1：请保持本终端打开。网页关闭、刷新或切后台不再结束授权。")
		fmt.Println("结束维修：关闭本终端、按 Control+C，或在状态页点击“停止授权”。不会安装后台服务。")
	}
	if !*headless {
		if e := openBrowser(url); e != nil {
			fmt.Println("自动打开浏览器失败，请复制上述本机地址。", e)
		}
	}
	<-app.ctx.Done()
	return nil
}
