# CLAUDE.md — trust-proxy

出入网流量控制 / 检测 / 异常行为识别网关。以 [sing-box](https://github.com/SagerNet/sing-box) 为数据面底座，
核心目标是识别出入网异常，尤其**木马/后门向外部机器回传机密数据（exfiltration / C2）**。

> 部署形态：**自用、不分发二进制**，因此不触发 sing-box 的 GPLv3 分发义务，自研代码可闭源。
> 一旦要把二进制交给第三方，须改走进程隔离或商业授权（详见文末「许可证」）。

---

## 架构

**单进程**：我们自己的 Go `main` 以库方式 `import` sing-box，一个二进制同时是数据面 + 控制面 + (未来)检测面。

```
                         我们的二进制 (github.com/ivanzzeth/trust-proxy)
  客户端 ──socks/http──▶ ┌─────────────────────────────────────────────────┐
     :17070             │ sing-box 核心 (route / sniff / 连接跟踪)          │──direct/代理──▶ 出网
                        │      │                         ▲                  │
                        │      │ AppendTracker(未来)     │ service/api      │
                        │      ▼                         │ (Connect/proto)  │
                        │  检测引擎(未来)           官方 React dashboard    │◀── 浏览器 :9095/dashboard/
                        │  信誉/beacon/外泄/断连     (webui/, 我们自维护)   │
                        └─────────────────────────────────────────────────┘
```

三层职责：

| 层 | 现状 | 实现 |
|---|---|---|
| **数据面** 代理/路由/分流/连接跟踪 | ✅ sing-box 原生 | `configs/config.json` 的 route 规则；**白名单默认拒绝**（allow-list 放行 + 末尾 `reject` 兜底）；`sniff` 取 SNI |
| **控制面/UI** | ✅ 里程碑 0 | 官方 dashboard（`webui/`），走 sing-box 内置 `service/api`（Connect/protobuf daemon，**非 Clash REST**） |
| **检测面** 异常/外泄识别 + 处置 | 🟡 里程碑 1（遥测 stub 已跑通） | `detector.go` 实现 `adapter.ConnectionTracker`，经 `Box.Router().AppendTracker` 挂上；当前记录每条放行连接，后续长检测算法 + 处置（wrap-close / Clash `DELETE /connections/{id}`） |

### 订阅 → apply（热重载）
- `internal/subscription`：抓取订阅 URL → 解析成节点（每个带完整 sing-box outbound JSON）。解析支持：① **sing-box JSON**（直取 outbounds，无损）② base64/明文 **share 链**（vless/trojan/ss/vmess/hysteria2/tuic，见 `convert.go`）。**Clash YAML 暂不支持**。
- **UA 门控**：机场常按 User-Agent 放行，generic UA 会 403。默认 UA=`clash-verge/v2.0.0`，可 `sub add --ua` 覆盖。**注意：机房/风险 IP 可能被机场拒发订阅内容——真实订阅要在本机（住宅 IP）测。**
- `gateway.Manager.Apply(nodes)`：JSON 层把节点 outbound 注入配置、把 `proxy` 组重建为 `urltest`（0 节点则退回 `selector[direct]`）→ `buildBox`(fresh ctx+parse+New+AppendTracker) → **先建新 box 成功才关旧的**（配置错误则旧 box 完好、apply 报错，不中断服务）→ Start 新 box。约束：sing-box 库模式无粒度热更，reload=重建实例，重建期间监听端口有短暂 blip。
- **apply 后**：白名单放行的流量走 `proxy` 组（即经订阅节点出网）。apply 死节点会导致放行流量断（urltest 无健康节点）；重启 serve 回到 base（proxy=selector[direct]）。

### 安全模型：白名单默认拒绝（重要）
出网默认**拒绝**，只放行 allow-list。黑名单追不完，白名单「未知即拒」才能卡死木马向任意 C2 回传。
sing-box 里的写法（`configs/config.json` 的 `route.rules`，顺序敏感）：
1. `{ "action": "sniff" }` — 先嗅探拿到 SNI/域名（非终结）。
2. allow-list：`domain_suffix` / `ip_cidr` 命中 → `{ "action": "route", "outbound": "direct" }`（终结、放行）。
3. 兜底：`{ "network": ["tcp","udp"], "action": "reject" }` — 其余全拒。
   （注意：**空 matcher 的 rule 非法**=`missing conditions`，所以兜底必须带 `network` 匹配器；`reject` 在 tracker 之前短路，故 detector 只看到「放行」的连接。）

### UI 分工（已决策）
官方 dashboard 是**运行时监控面板**（Overview/Connections/Logs/Groups/Tools），**不含**节点管理、订阅管理、多用户/配额——那些是 s-ui/3x-ui 这类「管理面板」的功能。决策：
- **官方 dashboard（`webui/`）保持不改**，只做运行时监控，挂在 `/dashboard/`，走 `service/api`（Connect）。**不改 → upstream 同步干净**。
- **节点管理、订阅管理、检测/告警** = 我们**自建的 React 应用 + 自建 Go `/api`**（REST/WS），后端负责订阅 URL 解析→生成 sing-box outbound→热重载、以及检测数据。订阅/配置生成逻辑**借鉴 s-ui 的 Go 实现**（github.com/alireza0/s-ui，Go+Vue，GPLv3）。
- 两个前端并存：`/dashboard/`（官方监控，只读运维）+ 我们的应用（管理+安全）。各连各的后端接口，互不耦合。

**为什么单进程**：深度检测（挂 tracker、镜像连接、自定义 outbound）必须和 sing-box 同进程；
纯元数据检测才可跨机。将来若要「一个控制台管多节点」，用「探针(数据面)+大脑(分析/UI)」分离，探针仍是本二进制。

### 单一二进制 + CLI/SDK 分层
一个二进制既是后端也是 CLI 客户端，靠子命令区分：
- `trust-proxy serve` — 跑网关（sing-box 数据面 + detection + 我们的后端 `/api`）。
- 其余子命令 = **CLI 客户端**，经 **Go SDK** 调运行中的后端。

**SDK 两层**（回应「先封装标准接口为底层原语，上层再易用封装」）：
- `pkg/clash` — **底层原语**：直连标准 **Clash API**（`/connections`、`DELETE /connections/{id}`、`/version`…）。通用、可复用于任何 sing-box/mihomo/clash。
- `pkg/client` — **上层易用**：调我们自己的 `/api`（订阅等），并**组合** `pkg/clash`（`client.Clash` 暴露原语，`client.Connections()/Kill()` 是便捷封装）。
- `pkg/apitypes` — 共享 wire 类型（无内部依赖，避免 import 环）。

CLI：`conn ls|kill`（底层原语，走 pkg/clash→:9090）；`sub add|ls|rm|refresh`（上层，走 pkg/client→:9096）。

### 关键文件 / 目录
```
main.go                    thin: cmd.Execute()
cmd/{root,serve,sub,conn}.go  cobra 命令
internal/gateway/          box 引导(Bootstrap) + detector(AppendTracker 检测器)
internal/api/              我们自己的后端 /api（stdlib mux；订阅 CRUD）
internal/subscription/     订阅 抓取/解析(base64+share链)/JSON 存储（借鉴 s-ui）
pkg/clash/                 底层 SDK：标准 Clash API 客户端
pkg/client/                上层 SDK：/api + 组合 clash
pkg/apitypes/              共享 wire 类型
configs/config.json        sing-box 配置：白名单默认拒绝 + clash_api + service/api(+dashboard)
third_party/sing-box       【上游子模块】testing 分支，replace 进本模块
webui/                     【上游 vendored 副本】官方 dashboard
data/                      运行时数据（subscriptions.json 等，gitignore）
```

### 数据面能力：现成 vs 自研
- **现成（配置即得）**：按 domain/geoip/ip/port/进程/rule-set/逻辑规则分流；`reject`/`block` 阻断；主动断连；
  连接级遥测（上下行字节、SNI、进程、命中规则、出站链）。
- **自研（检测大脑）**：异常判定（C2 信誉、beaconing、异常上行、DGA、DNS 隧道）、自动处置闭环、
  流量镜像给 DPI（自定义 outbound 包 `net.Conn` + TeeReader）、DLP、限速、告警/审计/UI。

---

## 从上游同步代码

有**两个**独立上游，同步方式不同。

### 1. sing-box（`third_party/sing-box`）— git 子模块，干净同步

跟踪 `testing` 分支（官方 dashboard 依赖的 `service/api` 尚未进稳定 tag；`AppendTracker` 稳定版已有）。

```bash
cd third_party/sing-box
git fetch origin
git checkout testing && git pull          # 或 checkout 某个具体 tag/commit 以 pin
cd ../..
go mod tidy                               # 重新解析 sing-box 的传递依赖
make build                                # 重编译验证
# 冒烟：make run，确认代理出网 + dashboard 正常
git add third_party/sing-box go.mod go.sum
git commit -m "chore: bump sing-box submodule to <ref>"
```

注意：
- **内部 Go API 无兼容承诺**（`adapter`/`trafficcontrol`/`route`）。升级后若 `main.go` 或未来的 tracker 编译失败，
  按新签名修。**能走 config(JSON) 表达的就别写死 Go 结构体**，减少受伤面。
- **build tags**：里程碑 0 无需 tag（`service/api` 无条件编译）。要 Clash API 加 `with_clash_api`，
  QUIC 加 `with_quic`，uTLS 加 `with_utls`（见 `Makefile` 的 `TAGS`）。
- 别盲目跟 `testing` HEAD，建议 pin 到具体 commit，升级当独立动作 + 回归。

### 2. 官方 dashboard（`webui/`）— vendored 副本，半手动同步

我们**克隆后删了它的 `.git`**，把源码并入本仓自行维护（因为要往里加安全检测视图）。
因此它不是子模块，同步需要「拉上游 → 合并进 `webui/`，保留我们的改动」。

**推荐：git subtree（一次性接上，之后可 pull）**
```bash
# 一次性：登记上游为远端
git remote add dashboard-upstream https://github.com/SagerNet/sing-box-dashboard

# 之后每次同步（--squash 把上游历史压成一个提交并入 webui/）
git subtree pull --prefix=webui dashboard-upstream main --squash
# 解决与我们本地改动的冲突后：
make webui && make run                     # 重新 generate+build 验证
```

**备选：手动 diff（无 git plumbing，适合改动很小时）**
```bash
git clone --depth 1 https://github.com/SagerNet/sing-box-dashboard /tmp/sbd
diff -ru --exclude=.git --exclude=node_modules --exclude=dist --exclude=src/gen webui /tmp/sbd
# 逐项把上游变更并进 webui/，保留我们自加的安全视图，然后 make webui 验证
```

同步 dashboard 后务必重跑构建链（它有代码生成步骤）：
```bash
git clone --depth 1 https://github.com/mbadolato/iTerm2-Color-Schemes \
    webui/vendor/iterm2-color-schemes && rm -rf webui/vendor/iterm2-color-schemes/.git   # 若缺
cd webui && corepack pnpm install --frozen-lockfile && corepack pnpm run generate && corepack pnpm run build
```
- 用 **pnpm**（`packageManager: pnpm@11.13.0`，`corepack` 自动取版本），不是 npm。
- **build 前必须 `generate`**：`buf generate` 把 `proto/daemon/started_service.proto` 生成到 `src/gen`，App 直接 import。
- 我们改造 dashboard 时，尽量**新增文件/视图**而非改上游文件，降低未来 subtree 合并冲突。

---

## 构建 / 运行 / 验证

```bash
make deps        # 首次：git submodule update --init --recursive（拉 sing-box）
make build       # 编译 -> ./trust-proxy（TAGS="with_clash_api ..." 可选）
make run         # 用 configs/config.json 启动
make webui       # 构建官方 dashboard -> webui/dist（pnpm install→generate→build）
```

验证（不影响本机 Surge：无 TUN、不改系统代理、端口错开）：
```bash
curl -x socks5h://127.0.0.1:17070 https://api.ipify.org          # 代理出网
curl -x socks5h://127.0.0.1:17070 https://ads.doubleclick.net    # 命中黑名单 -> 连接失败(reject)
curl -x socks5h://127.0.0.1:17070 https://example.com            # 正常 -> 200
# 浏览器打开 http://127.0.0.1:9095/  （跳 /dashboard/）
```

| 服务 | 地址 |
|---|---|
| 代理入站 (mixed socks/http) | `127.0.0.1:17070` |
| API / dashboard | `127.0.0.1:9095`（UI 在 `/dashboard/`） |

---

## 决策记录 & 坑（已验证）

- **底座选 sing-box**：可作 Go 库嵌入、TUN 网关成熟、连接遥测现成、协议最前沿（AnyTLS/Reality）。
  mihomo 是零成本平替（同 Clash API）；Xray-core 更适合当**墙外出口节点**（Reality 原产地，MPL 许可更宽松）。
- **抗封锁策略**：靠「多协议 + 自动 failover + 换 IP」的敏捷，而非押注单一静态协议。AnyTLS 现在存活好只是「新、没被针对」，非永久。
- **官方 dashboard 走 Connect/protobuf**（`service/api`），只在 sing-box `testing` 分支 → 子模块必须跟 testing。
  想用稳定版 v1.13.x：改用 `with_clash_api` + Clash 面板（zashboard/metacubexd）。
- **域名管控是 sing-box 原生**：`sniff` 取 SNI + `domain*` 规则 `reject`，零代码。动态「按行为决定挡谁」才是自研。
- dashboard：pnpm、必须先 generate、有 vendor 子模块、UI 路径 `/dashboard/`。
- 可再生目录已 gitignore：`webui/{dist,node_modules,src/gen,vendor/iterm2-color-schemes}`。

## 路线图
- **里程碑 0（✅）** 全栈跑通：Go 嵌入 sing-box + 代理 + 官方监控 UI。
- **里程碑 1（🟡 进行中）** ✅白名单默认拒绝 + ✅`AppendTracker` 检测器遥测 stub + ✅Clash API + ✅单一二进制 CLI/SDK 分层 + ✅订阅管理（抓取/解析/存储）+ ✅**订阅 apply（转换成 sing-box outbound + 热重载进 `proxy` 组）**。**待做**：自动处置闭环（检测异常 → `conn kill`）。
- **里程碑 2** 自建 React 应用（管理+安全）：白名单管理 + 连接/告警视图，接 `pkg/client`/`/api`。
- **后续** 元数据检测（信誉/beaconing/异常上行/进程归属）→ DPI/JA4/DLP（镜像明文腿）。

## 许可证
- sing-box / 官方 dashboard 均 **GPLv3（+ 命名附加条款）**。
- **自用不分发二进制**：GPLv3 分发义务不触发（非 AGPL，无联网条款），自研代码可闭源。
- 保留上游版权与 GPLv3 文本；不得用 sing-box 名号做宣传。
- 若将来要分发二进制：进程隔离 / 商业授权 / 开源，三选一，并请法务确认。
