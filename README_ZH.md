# awesomeC2

**AwesomeC2** 是一款专为高级红队（Red Team）行动设计的后渗透（post-exploitation）框架，专注于在现代且复杂的环境中开展渗透测试。本工具**仅限用于获得授权的对抗模拟（adversary emulation）及实验室环境测试**。

该项目包含：基于 Go 语言编写的服务器端（Server）与操作端（Operator）、基于 Go 的终端用户界面（TUI）、使用 C 语言编写的 Windows 客户端、轻量级 TLS/WebSocket 桥接程序、协议库以及部署示例。项目规模精简，便于阅读、审计和修改。

> **法律声明**
>
> 请仅在您拥有所有权或已获得明确书面授权的系统上使用本软件。在未经授权的情况下针对第三方系统运行本软件，在大多数司法管辖区均属违法行为。作者及贡献者不对任何滥用行为承担责任。

## 目录结构

| 路径 | 说明 |
| --- | --- |
| `server/` | Go 语言编写的 C2 服务器 (`cmd/server`) 和命令行操作端 (`cmd/operator`)，以及 `bdc2` 协议包 |
| `client/` | 兼容 Windows Server 2008 的 C 语言客户端（使用 MinGW-w64 编译，静态链接 msvcrt） |
| `tui/` | 供操作人员使用的 Go 终端用户界面 (TUI) |
| `tlsbridge/` | 轻量级 Windows TLS/WebSocket 桥接程序（基于 mbedTLS），用于受限的网络出站环境 |
| `tests/` | 协议测试、回环（loopback）测试及端到端测试 |
| `deploy/` | 服务器配置示例、Nginx 与 systemd 配置，以及客户端/操作端的启动脚本片段 |
| `docs/` | 协议、安全性、部署及客户端相关说明文档 |

## 功能特性

- 采用 24 字节的二进制帧头（`BDC2`，版本 1）及 TLV（Type-Length-Value）格式的有效载荷（payload）。
- 使用 AES-128-GCM 算法加密有效载荷，并将帧头作为附加认证数据（AAD）。
- 每个连接均拥有独立的会话密钥，该密钥通过 HKDF-SHA256 算法，结合预共享密钥（PSK）与客户端生成的随机数（nonce）派生而成。
- 包含基于 HMAC-SHA256 的 HELLO 握手验证及操作端（Operator）身份认证（AUTH）机制。
- 各通信方向均采用单调递增的序列号，并具备防重放（replay protection）功能。 - 极简的 RFC 6455 WebSocket 实现（包含客户端与服务端），支持 TLS。
- 具备任务队列、心跳/抖动机制、指数退避重连，以及基于 SHA-256 校验的文件上传/下载功能。
- Windows 客户端模块：Shell 交互、进程列表获取、文件读写、持久化辅助、凭据收集辅助、隧道代理、键盘记录、屏幕截图、清理痕迹及自毁功能。
- 操作端 CLI（命令行界面）与 TUI（终端用户界面），支持审计哈希链（`audit_hash_chain`）。
- 提供 nginx/Cloudflare 前置代理示例，以及适用于仅允许访问固定端点（出口受限）主机的本地 TLS 网桥。

## 快速入门（本地回环测试）

生成两个随机预共享密钥（PSK）：

```bash
openssl rand -base64 32
openssl rand -base64 32
```

将它们填入 `deploy/config.server.example.json` 的副本中（也可使用基于环境变量的配置）。随后执行：

```bash
cd server
go build -o ../bin/server.exe ./cmd/server
go build -o ../bin/operator.exe ./cmd/operator

cd ..
./bin/server.exe -config deploy/config.server.example.json
```

在 Windows 环境下构建客户端：

```bat
cd client
set C2_CLIENT_DOMAIN=127.0.0.1
set C2_CLIENT_PORT=9909
set C2_CLIENT_PATH=/ws
set C2_CLIENT_ID=client-01
set C2_CLIENT_PSK=base64:REPLACE_WITH_CLIENT_PSK
set C2_ALLOW_SHELL=1
build.cmd
```

构建过程会根据环境变量重新生成 `src/generated_config.h` 文件。该文件已被 Git 忽略，请务必不要将其包含真实密钥提交至版本库。针对本地 Operator 监听器运行 Operator：

```bat
set C2_OPERATOR_ADDR=127.0.0.1:9910
set C2_OPERATOR_USER=ops
set C2_OPERATOR_PSK=base64:REPLACE_WITH_OPERATOR_PSK
bin\operator.exe list
```

## 配置

所有地址、端口、PSK（预共享密钥）、PIN 码及构建标识符均在构建时或运行时提供。**本仓库中不应包含任何真实的 PSK、密钥、域名、IP 地址或目标标识符。**

- Server（服务端）：`deploy/config.server.example.json`
- Operator（操作端）：`deploy/config.operator.example.cmd`
- Client（客户端）构建/运行：`deploy/config.client.example.cmd`
- TLS 网桥：`tlsbridge --listen 127.0.0.1:1443 --connect <origin-ip>:443 --sni <origin-hostname>`
- TUI（终端用户界面）：通过环境变量及本地配置文件进行配置；详见 `tui/README.md`

请使用加密安全的来源生成 PSK。建议**为每个客户端和每个 Operator 分别配置独立的 PSK**。

## 构建

### Server 和 Operator

```bash
cd server
go test ./...
go build ./cmd/server ./cmd/operator
```

### TUI

```bash
cd tui
go build -o c2tui.exe .
```

TUI 的 `go.mod` 使用了本地 `replace` 指令指向 `../server`；除了 Go 工具链和已锁定的依赖项外，无需从网络获取任何模块。

### Windows 客户端

要求：具备针对 `x86_64-w64-mingw32` 目标的 MinGW-w64 环境、`objdump` 工具，以及兼容 Windows 的 `msvcrt` 运行时。所提供的 `build.cmd` 采用了“导入表网关”（import-table gate）技术，确保生成的结果能够兼容 Windows Server 2008，并避免了对 UCRT/VCRUNTIME 的依赖。

```bat
cd client
build.cmd --clean
set C2_CLIENT_DOMAIN=127.0.0.1
set C2_CLIENT_PORT=9909
set C2_CLIENT_PATH=/ws
set C2_CLIENT_ID=client-01
set C2_CLIENT_PSK=base64:...
set C2_ALLOW_SHELL=1
build.cmd
```

### TLS 网桥 (TLS bridge)

```bash
cd tlsbridge
./build.sh
# 或者，在安装了 MinGW 和 mbedTLS 的 Windows 环境下：
build.bat
```

该网桥旨在为旧版主机或出站流量受限的主机提供便利。它**不能**替代完善的 TLS 协议栈；目前仅支持可选的证书验证功能，配置时请务必谨慎。详情请参阅 `docs/SECURITY.md`。

## 协议概览

```text
帧 (Frame):
  魔数 (magic) "BDC2" | 版本 (version=1) | 类型 (type) | 标志 (flags) | 保留 (reserved)
  | 会话 ID (session_id, u64) | 序列号 (seq, u32) | 载荷长度 (payload_len, u32)
  | 载荷 (payload)

HELLO（明文 TLV）：
ID、操作系统 (OS)、架构 (arch)、版本 (ver)、进程 ID (pid)、随机数 (nonce)、MAC

MAC = HMAC-SHA256(预共享密钥 psk, "hello" || ID || 随机数)
密钥 (key) = HKDF-SHA256(预共享密钥 psk, ID || 随机数, "backd-c2-v1", 16)

后续所有帧：
AES-128-GCM(密钥, 随机数=[方向, 0..0, 序列号], 附加认证数据 AAD=头部[0:24])

完整的布局、消息类型以及操作员 RPC 定义，请参阅 `docs/PROTOCOL.md`。

## 安全性与局限性

本工具**并非**隐蔽型植入程序，也未声称具备不可检测性。它是一个轻量级、可审计的 C2（命令与控制）概念验证程序。主要局限性包括：

- 默认使用静态预共享密钥 (PSK)；不具备前向安全性 (Forward Secrecy)。
- 服务器负责终结内部协议；在示例部署中，TLS 由 nginx 或 Cloudflare 负责终结。
- 本仓库中的 TLS 网桥经过了极简化处理。证书验证为可选功能，若用于生产环境，必须将其启用。
- Windows 客户端仅为普通用户态进程，不包含内核驱动程序或 Rootkit。
- 操作员命令行界面 (CLI) 会输出任务结果；请勿将敏感信息（密钥等）记录到共享系统中。
- 审计哈希链仅在日志受到外部保护的情况下，才具备防篡改能力。

有关威胁模型及安全加固清单，请参阅 `docs/SECURITY.md`。

## 测试

```bash
cd server
go test ./...
cd ..
python tests/run_all.py --clients 20
```

Python 测试脚本要求在测试运行程序所在的同级目录下存在一个 `verify/` 目录，且该目录内需包含已编译好的 `server.exe`。具体目录结构请参阅 `tests/README.md`。

## 许可证

采用 MIT 协议。详情请参阅 `LICENSE`。
