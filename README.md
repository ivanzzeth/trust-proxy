# trust-proxy

出入网流量控制 / 检测 / 木马外泄识别网关，以 [sing-box](https://github.com/SagerNet/sing-box) 为数据面底座。

内网机器的出网流量经 trust-proxy 网关 → **白名单默认拒绝**（黑名单追不完，白名单才能卡死木马向任意 C2 回传）→ **检测**异常出网（威胁情报命中、异常大上传=疑似外泄）→ 经订阅/自建节点出口。

一个二进制，三种角色：

| 角色 | 命令 | 说明 |
|---|---|---|
| **客户端网关** | `trust-proxy serve` | mixed 入站(:17070) + 白名单 + 检测 + 控制台/API(:9096) |
| **TUN 全流量网关** | `sudo trust-proxy serve -c configs/config.tun.json` | 网络层接管**所有**出入网流量（木马裸 socket 也逃不掉），需 root，专用网关机 |
| **代理服务端（出口节点）** | `trust-proxy proxy run` / `proxy gen` | 自建任意协议出口节点 |

> **架构**：Go `main` 以库方式 `import` sing-box（`third_party/sing-box` 子模块）→ 数据面（代理/路由/连接跟踪）。检测/白名单/订阅/控制台是自研的控制面。自用不分发二进制，不触发 GPLv3 分发义务（详见 CLAUDE.md「许可证」）。

## 快速开始

依赖：Go 1.24.7+、Node 20+ / pnpm（构建控制台）。

```bash
make deps            # git submodule update --init --recursive（拉 sing-box，testing 分支）
make console         # 构建控制台(vendored Yacd) -> console/public
make build           # 编译 -> ./trust-proxy（默认 tags：clash_api quic utls grpc gvisor）
./trust-proxy serve  # 启动客户端网关
```

浏览器打开控制台（secret 预填）：**http://127.0.0.1:9096/?hostname=127.0.0.1&port=9090&secret=trust-proxy**

## 控制台（`console/`，基于 Yacd，React 19）

自研页（走后端 `/api`）：
- **订阅 / 节点**：三种添加方式 —— ① 订阅链接（可 `--via` 经代理抓取）② 手动填写（选协议出对应字段）③ 粘贴（share 链接 / base64 / Clash YAML / sing-box JSON）。列表可 **应用（热重载进 `proxy` 组）/ 刷新 / 删除**。
- **白名单**：出网允许清单（域名 → 走代理组出网；IP 段 → 直连），增删**即时热重载**生效。
- **告警**：出网审计 + 检测（威胁情报域名/IP 命中、≥10MiB 大上传=疑似外泄），告警高亮、只看告警、3s 刷新。
- \+ Yacd 原生监控：连接 / 日志 / 代理组 / 规则（走标准 Clash API）。

## 节点 / 订阅

- 解析支持：**sing-box JSON**（无损直取）、**Clash YAML**（含单个节点）、base64/明文 **share 链**。协议：vless(reality)、vmess、trojan、shadowsocks、anytls、hysteria2、tuic。
- 来源：http(s) URL、`file://` 本地文件、或直接粘贴内容。
- **抓取**用标准 TLS + 跟随重定向（`internal/subscription/fetch.go`）；`--via socks5://|http://` 可经指定代理出口抓取（绕开机场对来源 IP 的封锁）。
- CLI：`sub add <url> [--via ..]` / `sub import [file]`（stdin 亦可）/ `sub ls` / `sub apply <id>` / `sub refresh` / `sub rm`。

## 一键部署代理服务端

```bash
./trust-proxy proxy gen --type <协议> --server <你的服务器IP> --port 443
#   协议: shadowsocks | vless-reality | vless | vmess | trojan | anytls | hysteria2 | tuic
#   输出：服务端 config + 客户端节点(Clash dict，可粘进控制台导入)
#   TLS 类自动内联自签证书(客户端 skip-cert-verify)；vless-reality 免证书自动生成密钥对
./trust-proxy proxy run -c server.json          # 在服务器上运行
```

## TUN 全流量网关

```bash
sudo ./trust-proxy serve -c configs/config.tun.json
```
`tun` 入站 + `auto_route` 网络层接管全部出入网流量。需 **root**，与其它 TUN 工具（Surge 增强模式等）互斥 → 用于专用网关机/软路由。检测与白名单逻辑不变。

## CLI / SDK

- SDK 分层：`pkg/clash`（标准 Clash API 原语，可复用于任何 sing-box/mihomo/clash）+ `pkg/client`（trust-proxy 易用封装，组合 clash）。
- 低层原语：`conn ls` / `conn kill <id|all>`（走 Clash API）。
- 高层：`sub *`（走后端 `/api`）。

## 端口（均绑 loopback）

| 服务 | 地址 |
|---|---|
| 代理入站 (mixed) | `127.0.0.1:17070` |
| Clash API（`pkg/clash` 消费，secret=`trust-proxy`） | `127.0.0.1:9090` |
| 官方 sing-box dashboard（可选，service/api） | `127.0.0.1:9095` |
| **后端 /api + 控制台** | `127.0.0.1:9096` |

客户端网关默认不开 TUN、不改系统代理，与本机 Surge 等互不干扰。

## 目录

```
main.go                  cmd.Execute()
cmd/                     cobra 命令：serve / proxy / sub / conn
internal/gateway/        box 引导 + 热重载(节点/白名单注入) + detector 挂载
internal/detect/         检测引擎（事件环形缓冲 + 字节计数 + 规则）
internal/subscription/   订阅 抓取/解析/存储 + 转换(share链/clash → sing-box outbound)
internal/whitelist/      出网白名单存储
internal/api/            后端 /api（订阅/白名单/事件/连接代理）+ serve 控制台
pkg/clash, pkg/client, pkg/apitypes   SDK
console/                 控制台（vendored Yacd，自维护，+ 我们的页面）
webui/                   官方 sing-box dashboard（vendored，可选监控）
configs/config.json      客户端网关配置（mixed + sniff + reject + 注入白名单）
configs/config.tun.json  TUN 网关配置
third_party/sing-box     子模块（testing 分支），replace 进本模块编译
data/                    运行时数据（subscriptions.json / whitelist.json，gitignore）
```

## 上游同步 & 更多细节

见 [CLAUDE.md](./CLAUDE.md)：架构、sing-box 子模块 vs vendored 前端的同步方式、build tags、已踩的坑、路线图、许可证边界。
