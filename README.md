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
make dashboard       # 构建控制台(shadcn/ui) -> dashboard/dist
make build           # 编译 -> ./trust-proxy（默认 tags：clash_api quic utls grpc gvisor）
./trust-proxy serve  # 启动客户端网关
```

启动时 Clash secret 随机生成并持久化到 `data/clash-secret`（浏览器不碰它——控制台单一 origin，Clash 数据由后端 `/api` 代理）。`serve` 日志打印控制台 URL：`http://127.0.0.1:9096/`。

## 控制台（`dashboard/`，shadcn/ui + Tailwind，React 19）

自研页（走后端 `/api`）：
- **订阅 / 节点**：三种添加方式 —— ① 订阅链接（可 `--via` 经代理抓取）② 手动填写（选协议出对应字段）③ 粘贴（share 链接 / base64 / Clash YAML / sing-box JSON）。列表可 **应用（热重载进 `proxy` 组）/ 刷新 / 删除**。
- **配置档（Profiles）**：把「应用的订阅 + 白名单 + 启用的规则集 + 抓取模式」打包成命名档，一键切换＝一次热重载整体换（如 strict-gateway ↔ permissive）。「保存当前为配置档」即快照当前状态。
- **白名单**：出网允许清单（域名 → 走代理组出网；IP 段 → 直连）+ **进程放行**（可选：一旦非空，不在列表内的进程连接全部拒绝——未知二进制/木马即便去白名单目标也出不了网）+ **设备放行**（可选：`source_ip_cidr` 来源白名单，网关模式下只放行已知设备）。增删**即时热重载**生效；非法条目（如把域名填进 IP）被拒绝且不落盘，已污染的存储在重启加载时自动清洗。
- **规则集（Rule Sets）**：一键导入公开 sing-box `rule_set`（内置目录：geosite-cn/geoip-cn 直连、geosite-geolocation-!cn 走代理、category-ads-all 拦截；或按 URL 加 `.srs`/`.json`）。每条选角色 **block / allow-direct / allow-proxy**，注入顺序保持默认拒绝语义（block 在白名单之上、allow 在兜底 reject 之前）。`download_detour` 固定 `direct`（默认拒绝下否则拉不到规则会死锁），开启 `cache_file` 持久化下载。
- **连接**（一个页面三标签 **全部 / 活动 / 已关闭**）：活动连接来自 Clash API（可断开单条/全部）；已关闭来自我们持久化的连接历史。每行带**状态**（活动/已放行/**已拦截**）；**被拦截的连接也可见**（兜底路由到 `block` 出站而非 reject，detector 记录并拿到 sniff 到的 SNI 域名）。每行**一键加白**：`+域名` / `+IP` / `+进程` / `+设备`（来源 IP）—— 第一次被拦，直接点一下就放行（热重载）；`+IP` 仅在目标确为 IP 时出现（域名请用 `+域名`）。检测项：威胁情报域名/IP 命中、≥10MiB 大上传=疑似外泄、**beaconing（周期性回连=疑似 C2 心跳）**，命中高亮、可只看告警。
- **顶栏常驻**：抓取模式切换（手动 / 系统代理 / TUN）+ 威胁自动阻断开关 + 实时流量 + 威胁情报计数 + 明暗主题。
- **Proxies / Logs**：出站组（节点选择 + 延迟测速）与实时日志流，均由后端代理 Clash API（浏览器不碰 secret）。

## 抓取模式 / 检测处置（运行时可切换）

- **模式**：`manual`（指 127.0.0.1:17070）/ `system`（设为系统代理）/ `tun`（网络层全接管，需 root）。控制台侧边栏或 `POST /api/mode` 热切换；TUN 无 root 会**自动回滚**上个模式、网关不掉线。`serve --mode` 指定初始模式。
- **威胁情报 feed**：默认拉 abuse.ch Feodo C2 IP 黑名单（CC0），后台定时刷新替换。`--threat-feeds`（逗号多源）/`--threat-refresh`/`--no-threat-feed`。
- **自动处置**：`--auto-block`（默认开）命中威胁的连接直接断；控制台可切换。
- **事件持久化**：审计事件 `data/events.json` 定时 + 退出快照，重启恢复。

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
./trust-proxy proxy run -c server.json              # 前台运行
./trust-proxy proxy run -c server.json --daemon     # 后台守护（脱离终端，SSH 断开不受影响）
./trust-proxy proxy stop                            # 停止守护进程（读 trust-proxy.pid）
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
| Clash API（`pkg/clash` 消费，secret 见 `data/clash-secret`） | `127.0.0.1:9090` |
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
internal/api/            后端 /api（订阅/白名单/规则集/配置档/事件 + 代理 Clash proxies/logs）+ serve 控制台
pkg/clash, pkg/client, pkg/apitypes   SDK
dashboard/               控制台（shadcn/ui + Tailwind + React 19，自研，走 /api 单一 origin）
webui/                   官方 sing-box dashboard（vendored，可选监控 :9095）
configs/config.json      客户端网关配置（mixed + sniff + reject + 注入白名单）
configs/config.tun.json  TUN 网关配置
third_party/sing-box     子模块（testing 分支），replace 进本模块编译
data/                    运行时数据（subscriptions.json / whitelist.json，gitignore）
```

## 许可证与归属

本项目以 **GPLv3** 授权（见 [LICENSE](./LICENSE)），因为它链接/内嵌了 GPLv3 的上游代码。分发本项目源码或二进制须遵守 GPLv3（保留声明、随附对应源码）。

上游组件：
- [sing-box](https://github.com/SagerNet/sing-box) — 数据面（子模块），**GPLv3**（+ 命名附加条款：衍生品不得使用其名称做宣传）
- [shadcn/ui](https://ui.shadcn.com) + [Radix UI](https://www.radix-ui.com) — 控制台组件（`dashboard/`），MIT
- [sing-box-dashboard](https://github.com/SagerNet/sing-box-dashboard) — 可选官方监控面板（`webui/`），GPLv3

## 上游同步 & 更多细节

见 [CLAUDE.md](./CLAUDE.md)：架构、sing-box 子模块 vs vendored 前端的同步方式、build tags、已踩的坑、路线图、许可证边界。
