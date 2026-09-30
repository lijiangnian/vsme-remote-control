# SignPath 申请草稿（未提交）

Project: VSME Remote Control
Repository: https://github.com/lijiangnian/vsme-remote-control (pending creation)
License: Apache-2.0
Maintainer: lijiangnian (repository owner; confirm MFA and signing roles)

Our project provides user-authorized, temporary remote maintenance for Windows
and macOS computers. Two explicitly paired Windows controllers can run diagnostic
commands, receive user-requested system information and transfer authorized files.
There is no hidden installation, automatic start-up or default cloud telemetry.
The public candidate does not contain company credentials or pre-authorized devices.

Windows uses a .NET Framework native UI embedding a Go maintenance engine. We
intend to sign the engine first, embed those signed bytes into the UI, then sign
the UI. Both stages are built on GitHub-hosted runners from the public repository,
with fixed product/version metadata and manual release approvals. We would like
review of this two-stage origin-verification configuration before relying on it.

This is a new project. We do not claim an established public reputation, approved
certificates, or current signed releases. Public release documentation and verified
CI runs will be provided before a formal application. Please advise whether the
project is eligible under your authorized remote-administration policies and what
additional review is required.

提交前缺项：公开仓库实际链接、通过的 CI、已发布开发版、隐私与权限操作演示、维护者角色/MFA、私密漏洞报告渠道、SignPath 两阶段构建来源审核。不得填写“已有可信签名”。
