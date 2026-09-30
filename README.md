# VSME Remote Control — 远程控制开源候选版

这是用于审阅、构建和申请可信代码签名的候选源码，不是已签名正式版。当前没有 SignPath 批准、没有可信签名证书，也没有 Windows 智能应用控制放行保证。不要用它替换现有生产版本。

Windows 原生窗口管理临时 Windows/macOS 被控端；两台明确配对的 Windows 主控可以互控。支持系统信息、命令任务、文件传输和任务审计。这里的“控制”是后台命令与文件操作，不包含屏幕画面、鼠标键盘控制。

## 权限与隐私

被控端以启动账户权限运行；管理员/root 启动意味着配对主控可执行管理员级命令。仅在设备所有者知情同意后运行。关闭程序撤销该程序的临时会话并终止其任务；已经执行的系统修改不会自动回滚。Mac 的状态网页不是授权生命周期开关，启动终端才是。详见 [PRIVACY.md](PRIVACY.md) 和 [SECURITY.md](SECURITY.md)。

公开版本不附带公司接入配置、私钥、服务器绑定或既有 SSH 授权；也不安装常驻服务、不设开机启动、不关闭安全防护。外部地址目录在候选版中禁用。

## 构建（Windows / PowerShell 7）

依赖 Go 1.24 或更高、Windows .NET Framework C# 编译器。运行：

```powershell
pwsh -File tools/Audit-PublicSource.ps1
pwsh -File tools/Build.ps1 -Stage Cores -Version 2.1.2.0
# 仅供开发构建；下面生成的 EXE 依然没有可信签名：
pwsh -File tools/Build.ps1 -Stage Wrappers -Version 2.1.2.0 -UnsignedDevelopmentOnly
```

核心运行时只依赖 Go 标准库。构建时固定使用 MIT 许可的 goversioninfo v1.7.0 生成 Windows 产品/版本资源；下载通过 Go 模块校验。Mac 二进制是交叉构建的开发产物，不代表已获得 Apple Developer ID 签名或公证。

## 首次配对（部署管理员）

1. 在每台 Windows 主控上用主控程序 `--export-profile` 导出各自配置。导出内容含 **接入密钥**，不是可以公开的资料。证书私钥留在本机。
2. 用可信方式核验两台主控证书指纹，把这两份对象组成 JSON 数组；保存为本地 `%APPDATA%\VSME-RemoteControl-OSS\fleet.json`。
3. 把该部署配置以可信方式交给已授权被控电脑，放在同一用户配置目录；Mac 默认目录是 `~/Library/Application Support/VSME-RemoteControl-OSS/fleet.json`。以 root 启动时请确认使用实际运行账户的数据目录，或使用 `--data` 明确指定；不要猜测用户目录。
4. 主控的名称、证书和接入密钥必须与本机实际身份一致才能监听。名称本身不是授权凭据。
5. Windows 被控端管理员打开后确认临时维修授权。Mac 当前需在可见终端运行相应芯片二进制，知情同意其 root 权限；候选版尚未提供正式安装器。

配置不嵌入公开二进制，不上传仓库、不发到公共群。安装该部署配置即决定允许哪两台主控，请勿导入陌生来源的配置。IP 分享文字只改变已配对主控的寻找地址，不更换主控证书或授予新身份。

## Code signing policy

见 [SIGNING.md](SIGNING.md)。计划申请 SignPath Foundation 的开源签名，但当前 **未申请完成、未批准、未签名**。维护者、审阅者和签名批准者拟由仓库所有者 `lijiangnian` 承担，正式申请时需确认角色并开启 MFA。所有签名发布需人工批准；不能给外部 PR 发送签名令牌。

签名順序：内部引擎 → 签内部引擎 → 嵌入原生外壳 → 签外壳 → 校验外壳和嵌入引擎 → 打包。

## 许可证

Apache-2.0，见 [LICENSE](LICENSE)。商标与品牌标识不因此授予通用使用权。公开候选版不包含公司的原始 Logo 图片或图标。
