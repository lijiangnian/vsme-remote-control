# Code signing policy 与申请进度

2026-09-30：公开仓库已创建，脱敏源码已上传，GitHub-hosted CI 已通过。没有签名证书、SignPath 账号配置或批准记录；申请尚未提交。不能保证申请通过，也不能给出批准日期。

仓库：https://github.com/lijiangnian/vsme-remote-control 。已通过的公开源码构建：https://github.com/lijiangnian/vsme-remote-control/actions/runs/36691615885 ，源码提交 `da2a479e4b8356f0dcad2e848f71974b04e33de6`。此构建只产出未签名开发二进制，不是可信发布。

## 选择与边界

计划申请 [SignPath Foundation](https://signpath.org/apply) 免费开源签名。Apache-2.0 只是条件之一，还需公开、维护、已发布、功能和隐私说明、可验证构建、项目信誉及人工审核。[资格与条件](https://signpath.org/terms.html)。它不是借用别人的证书，也不允许将公司二进制冒充公开源码产物。

获批后证书发布者是 SignPath Foundation，不是随意填写的 VSME 公司认证。批准后才能添加 “Free code signing provided by SignPath.io, certificate by SignPath Foundation” 说明；现在不能声称已获服务。

## 两阶段构建与签名

1. `tools/Build.ps1 -Stage Cores` 测试公开源码，生成 `artifacts/Core/Control-core.exe` 与 `Agent-core.exe`，以及 Mac 开发二进制。
2. 上传这两个内部引擎为 GitHub Actions artifact，使用 SignPath `cores.xml` 人工批准签名，下载签名结果到原路径。
3. `tools/Build.ps1 -Stage Wrappers` 先检查内部引擎的受信任 RSA 签名和时间戳，随后编译嵌入这些签名字节的原生窗口。
4. 上传两个外壳，使用 `wrappers.xml` 进行第二次签名；无需重建或重新修改签过名的引擎。
5. `tools/Verify-Signatures.ps1` 检查内外签名、嵌入资源的 SHA256、签名者和版本；失败禁止作为可信发布上传。

开发用 `-UnsignedDevelopmentOnly` 明确允许未签名本地外壳编译，不能用这个开关发布可信签名版本。内部引擎与外壳签好后应再打包、计算最终哈希；签名前的哈希不会保持不变。

## GitHub / SignPath 管理员配置

公开仓库为 `lijiangnian/vsme-remote-control`。仍需要所有者安装官方 SignPath GitHub App 并授予该仓库访问，开启 MFA，建立签名批准角色。现有代码不是上述服务的正式审批结果。

批准后配置 GitHub secrets `SIGNPATH_API_TOKEN`，变量 `SIGNPATH_ORGANIZATION_ID`、`SIGNPATH_PROJECT_SLUG`、`SIGNPATH_POLICY_SLUG`、`SIGNPATH_SIGNER_THUMBPRINT`（由服务确认的签名证书指纹）；对应项目配置 `cores` 与 `wrappers` artifact configuration。令牌不可写入 YAML、日志、源码或 ZIP。

CI 工作流在公开仓库运行；签名工作流仅人工触发，生产签名环境需 GitHub 人工批准，再加 SignPath 每次人工批准。具体参数须按服务分配值设置，不臆造 organization id 或已批准 policy。

微软要求智能应用控制使用受信任提供者的 RSA 代码签名，当前不支持 ECC Authenticode；这与应用内部 P256 TLS 认证是不同用途。[微软说明](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/code-signing-for-smart-app-control)。签名后仍需在目标受阻电脑实测。

Mac 还需独立 Apple Developer ID 签名、公证与真机验证；Windows 签名不能解决 Gatekeeper。
