# trust-proxy

出入网流量控制 / 检测 / 异常行为识别网关，以 [sing-box](https://github.com/SagerNet/sing-box) 为数据面底座。

- **数据面**：Go 后端以库方式 `import` sing-box（`third_party/sing-box` 子模块），负责代理、路由、分流、连接跟踪。
- **控制面 / UI**：克隆官方 [sing-box-dashboard](https://github.com/SagerNet/sing-box-dashboard)（React 19 + Vite + TS）自行维护，通过 sing-box 内置的 `service/api`（Connect/protobuf daemon）通信。
- **检测层**：`detector.go` 通过 `route.Router.AppendTracker` 把每条**放行**连接喂进自研引擎（当前为遥测 stub），后续做 C2 信誉匹配、beaconing、异常上行、数据外泄识别，并以断连处置。
- **安全模型**：出网**白名单默认拒绝**（allow-list 放行 + 末尾 `reject` 兜底）。黑名单追不完，白名单才能卡死木马向任意 C2 回传。

> 自用部署，不分发二进制，故不触发 sing-box 的 GPLv3 分发义务。

## 里程碑 0（已跑通）

单进程：Go 后端启动 sing-box + 代理入站 + 内置 API/dashboard + 域名黑名单。已验证：代理出网、域名 `reject`、API 服务、dashboard serving，且不与本机 Surge 冲突（无 TUN、不改系统代理、端口错开）。

### 依赖
- Go 1.24.7+
- Node 20+（构建 dashboard）

### 首次拉取子模块
```bash
make deps            # git submodule update --init --recursive
```
sing-box 子模块跟踪 `testing` 分支——官方 dashboard 依赖的 `service/api` 尚未进入稳定 tag（v1.13.x 无此模块）。

### 跑起来（单一二进制，子命令区分）
```bash
make build                 # 编译 -> ./trust-proxy（默认带 with_clash_api）
./trust-proxy serve        # 跑网关：sing-box + detection + 后端 /api(:9096)

# 另开终端，CLI 即客户端（经 Go SDK 调后端）：
./trust-proxy sub add https://airport.example/subscribe --name my-airport  # 订阅(抓取+解析)
./trust-proxy sub ls                      # 列出订阅+节点数
./trust-proxy sub apply <id>              # 把订阅节点热重载进 `proxy` 组（白名单放行流量即经其出网）
./trust-proxy conn ls                     # 活动连接(底层 Clash 原语)
./trust-proxy conn kill <id|all>          # 断连
```
解析支持 **sing-box JSON**（无损）、**Clash YAML**、base64/明文 **share 链**（vless/trojan/ss/vmess/hysteria2/tuic）。来源可为 http(s) URL 或 **`file://` 本地文件**。

抓取用 **uTLS 伪装 Chrome 指纹**（`internal/subscription/fetch.go`），绕过机场按客户端指纹识别的 WAF——trust-proxy 自主抓取，无需外部客户端。
极端情况仍可用本地文件兜底（如 clash-verge 的 profile）：
> `./trust-proxy sub add "file://$HOME/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/profiles/<uid>.yaml" --name my`
SDK 分层：`pkg/clash`（标准 Clash API 原语，可复用）+ `pkg/client`（trust-proxy 易用封装，组合 clash）。

验证（白名单默认拒绝）：
```bash
# 白名单内 -> 放行
curl -x socks5h://127.0.0.1:17070 https://api.ipify.org         # 200
curl -x socks5h://127.0.0.1:17070 https://example.com           # 200
# 非白名单 -> 默认拒绝
curl -x socks5h://127.0.0.1:17070 https://www.google.com        # 连接失败 (reject)
# detector 遥测（每条放行连接）在 stdout：形如 "[detector] allow tcp host=... rule=... out=..."
# Clash API：
curl -H "Authorization: Bearer trust-proxy" http://127.0.0.1:9090/connections
```
在 `configs/config.json` 的 `route.rules` 里增删 `domain_suffix` / `ip_cidr` 白名单条目即可调整放行范围。

### 接官方 WebUI（已在本仓 webui/ 落地并验证）
```bash
# 克隆官方 dashboard 进 webui/，去掉它的 .git 变成我们自己的副本
git clone https://github.com/SagerNet/sing-box-dashboard webui && rm -rf webui/.git
# 它依赖一个 vendor 子模块（生成终端主题用），单独拉一份
git clone --depth 1 https://github.com/mbadolato/iTerm2-Color-Schemes \
    webui/vendor/iterm2-color-schemes && rm -rf webui/vendor/iterm2-color-schemes/.git

make webui           # pnpm install -> pnpm run generate(buf 生成 protobuf 客户端) -> build -> webui/dist
make run             # 浏览器打开 http://127.0.0.1:9095/  (会跳 /dashboard/)
```
- 用 **pnpm**（仓库带 `pnpm-lock.yaml`，`packageManager: pnpm@11.13.0`，用 `corepack` 自动取对版本）。
- `build` 前必须 `generate`：`buf generate` 把 `proto/daemon/started_service.proto` 生成到 `src/gen`，App 直接 import 它。
- Dashboard 通过 Connect/protobuf 连 `service/api`（:9095），非 Clash REST。

## 端口
| 服务 | 地址 | 说明 |
|---|---|---|
| 代理入站 (mixed) | `127.0.0.1:17070` | socks/http 混合，验证用 |
| API / dashboard | `127.0.0.1:9095` | 官方 UI 对接口 (Connect/protobuf) |
| Clash API | `127.0.0.1:9090` | 底层 SDK(pkg/clash)消费 (REST/WS)，secret=`trust-proxy` |
| 后端 /api | `127.0.0.1:9096` | 我们自己的 API，上层 SDK(pkg/client)消费（订阅等） |

均绑 loopback。**别开 TUN / 别设系统代理**，以免与 Surge 等打架。

## Build tags
里程碑 0 无需任何 tag（`service/api` 无条件编译）。后续按需在 `make build TAGS="..."` 加：
- `with_clash_api` — 额外暴露 Clash REST/WS（可挂 zashboard / metacubexd）
- `with_quic` — Hysteria2 / TUIC / QUIC 嗅探
- `with_utls` — uTLS 指纹

## 目录
```
main.go              # 启动入口：include.Context -> 解析 config -> box.New -> Start
configs/config.json  # sing-box 配置：mixed 入站 + sniff + 域名 reject + api service
third_party/sing-box # 子模块 (testing)，replace 进本模块编译
webui/               # 克隆的官方 dashboard（自维护），build 到 webui/dist
```

## 稳定版退路
若不想跟 `testing`：把子模块切到 `v1.13.14`，改用 `-tags with_clash_api` 暴露 Clash API，UI 换成 zashboard / metacubexd（走 Clash REST，非官方 React dashboard）。
